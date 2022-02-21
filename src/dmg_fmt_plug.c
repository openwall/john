/*
 * DMG cracker patch for JtR. Hacked together during August of 2012
 * by Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * This software is
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2015, magnum
 * and is based on "dmg.c" from
 *
 * hashkill - a hash cracking tool
 * Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * References:
 *
 * http://lingrok.org/xref/syslinux/utils/isohybrid.c#apple_part_header
 * http://www.dubeyko.com/development/FileSystems/HFSPLUS/hexdumps/hfsplus_volume_header.html
 */

/*
 *  Debug levels:
 *   1 show what "test" hits
 *   2 dump printables from the decrypted blocks
 *   3 dump hex from the decrypted blocks
 *   4 dump decrypted blocks to files (will overwrite with no mercy):
 *       dmg.debug.main   main block
 *       dmg.debug        alternate block (if present, this is the start block)
 */
//#define DMG_DEBUG		2

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_dmg;
#elif FMT_REGISTERS_H
john_register_one(&fmt_dmg);
#else

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <openssl/des.h>
#ifdef DMG_DEBUG
#include <sys/file.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "aes.h"
#include "hmac_sha.h"
#include "jumbo.h"
#include "params.h"
#include "johnswap.h"
#include "common.h"
#include "formats.h"
#include "dmg_common.h"
#include "pbkdf2_hmac_sha1.h"
#include "loader.h"
#include "logger.h"

#define FORMAT_LABEL        "dmg"
#define FORMAT_NAME         "Apple DMG"
#define FORMAT_TAG           "$dmg$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME      "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " 3DES/AES"
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 3DES/AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define BINARY_SIZE         0
#define PLAINTEXT_LENGTH	125
#define SALT_SIZE           sizeof(struct custom_salt)
#define BINARY_ALIGN		1
#define SALT_ALIGN			sizeof(int)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           1 // MKPC and scale tuned for i7
#endif

#undef HTONL
#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
		((((unsigned long)(n) & 0xFF00)) << 8) | \
		((((unsigned long)(n) & 0xFF0000)) >> 8) | \
		((((unsigned long)(n) & 0xFF000000)) >> 24))

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct custom_salt {
	unsigned int saltlen;
	unsigned char salt[20];
	unsigned int ivlen;
	unsigned char iv[32];
	int headerver;
	unsigned char chunk[8192];
	uint32_t encrypted_keyblob_size;
	uint8_t encrypted_keyblob[128];
	unsigned int len_wrapped_aes_key;
	unsigned char wrapped_aes_key[296];
	unsigned int len_hmac_sha1_key;
	unsigned char wrapped_hmac_sha1_key[300];
	char scp; /* start chunk present */
	unsigned char zchunk[4096]; /* chunk #0 */
	int cno;
	int data_size;
	unsigned int iterations;
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked = mem_calloc_align(sizeof(*cracked),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	char *p;
	int headerver;
	int res, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$dmg$" marker */
	if ((p = strtokm(ctcopy, "*")) == NULL)
		goto err;
	headerver = atoi(p);
	if (headerver == 2) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt len */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 20)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
			goto err;
		if (hexlenl(p, &extra) / 2 != res || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* ivlen */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (atoi(p) > 32)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
			goto err;
		if (hexlenl(p, &extra) / 2 != res || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* encrypted_keyblob_size */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 128)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* encrypted keyblob */
			goto err;
		if (hexlenl(p, &extra) / 2 != res || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* chunk number */
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* data_size */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if ((p = strtokm(NULL, "*")) == NULL)	/* chunk */
			goto err;
		if (hexlenl(p, &extra) / 2 != res || extra)
			goto err;
		if (res > 8192)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* scp */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		/* FIXME: which values are allowed here? */
		if (res == 1) {
			if ((p = strtokm(NULL, "*")) == NULL)	/* zchunk */
				goto err;
			if (strlen(p) != 4096 * 2)
				goto err;
		}
	}
	else if (headerver == 1) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt len */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 20)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
			goto err;
		if (hexlenl(p, &extra) / 2 != res || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* len_wrapped_aes_key */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 296)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* wrapped_aes_key  */
			goto err;
		if (hexlenl(p, &extra) / 2 != res || extra)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* len_hmac_sha1_key */
			goto err;
		if (!isdec(p))
			goto err;
		res = atoi(p);
		if (res > 300)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* hmac_sha1_key */
			goto err;
		if (strlen(p) / 2 != res)
			goto err;
	}
	else
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "*");
	cs.headerver = atoi(p);
	if (cs.headerver == 2) {
		p = strtokm(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.saltlen; i++)
			cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.ivlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.ivlen; i++)
			cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.encrypted_keyblob_size = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.encrypted_keyblob_size; i++)
			cs.encrypted_keyblob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.cno = atoi(p);
		p = strtokm(NULL, "*");
		cs.data_size = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.data_size; i++)
			cs.chunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.scp = atoi(p);
		if (cs.scp == 1) {
			p = strtokm(NULL, "*");
			for (i = 0; i < 4096; i++)
				cs.zchunk[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
		if ((p = strtokm(NULL, "*")))
			cs.iterations = atoi(p);
		else
			cs.iterations = 1000;
	}
	else {
		p = strtokm(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.saltlen; i++)
			cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.len_wrapped_aes_key = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.len_wrapped_aes_key; i++)
			cs.wrapped_aes_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		p = strtokm(NULL, "*");
		cs.len_hmac_sha1_key = atoi(p);
		p = strtokm(NULL, "*");
		for (i = 0; i < cs.len_hmac_sha1_key; i++)
			cs.wrapped_hmac_sha1_key[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		if ((p = strtokm(NULL, "*")))
			cs.iterations = atoi(p);
		else
			cs.iterations = 1000;
	}
	if (cs.iterations == 0)
		cs.iterations = 1000;
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static int apple_des3_ede_unwrap_key1(const unsigned char *wrapped_key, const int wrapped_key_len, const unsigned char *decryptKey)
{
	DES_key_schedule ks1, ks2, ks3;
	unsigned char TEMP1[sizeof(cur_salt->wrapped_hmac_sha1_key)];
	unsigned char TEMP2[sizeof(cur_salt->wrapped_hmac_sha1_key)];
	unsigned char IV[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
	int outlen, i;

	DES_set_key_unchecked((DES_cblock*)(decryptKey +  0), &ks1);
	DES_set_key_unchecked((DES_cblock*)(decryptKey +  8), &ks2);
	DES_set_key_unchecked((DES_cblock*)(decryptKey + 16), &ks3);
	DES_ede3_cbc_encrypt(wrapped_key, TEMP1, wrapped_key_len, &ks1, &ks2, &ks3,
	                     (DES_cblock*)IV, DES_DECRYPT);

	outlen = check_pkcs_pad(TEMP1, wrapped_key_len, 8);
	if (outlen < 0)
		return 0;

	for (i = 0; i < outlen; i++)
		TEMP2[i] = TEMP1[outlen - i - 1];

	outlen -= 8;
	DES_ede3_cbc_encrypt(TEMP2 + 8, TEMP1, outlen, &ks1, &ks2, &ks3,
	                     (DES_cblock*)TEMP2, DES_DECRYPT);

	outlen = check_pkcs_pad(TEMP1, outlen, 8);
	if (outlen < 0)
		return 0;

	return 1;
}

static void hash_plugin_check_hash(int index)
{
	unsigned char hmacsha1_key_[20];
	unsigned char aes_key_[32];
	int j;

	if (cur_salt->headerver == 1) {
#ifdef SIMD_COEF_32
		unsigned char *derived_key, Derived_key[SSE_GROUP_SZ_SHA1][32];
		int lens[SSE_GROUP_SZ_SHA1], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA1];
		union {
			uint32_t *pout[SSE_GROUP_SZ_SHA1];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = (uint32_t*)(Derived_key[i]);
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, cur_salt->salt, 20,
			cur_salt->iterations, &(x.poutc), 32, 0);
#else
		unsigned char derived_key[32];
		const char *password = saved_key[index];
		pbkdf2_sha1((const unsigned char*)password, strlen(password),
		       cur_salt->salt, 20, cur_salt->iterations, derived_key, 32, 0);
#endif
		j = 0;
#ifdef SIMD_COEF_32
		for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		derived_key = Derived_key[j];
#endif
		if (apple_des3_ede_unwrap_key1(cur_salt->wrapped_aes_key, cur_salt->len_wrapped_aes_key, derived_key) &&
		    apple_des3_ede_unwrap_key1(cur_salt->wrapped_hmac_sha1_key, cur_salt->len_hmac_sha1_key, derived_key)) {
			cracked[index+j] = 1;
		}
#ifdef SIMD_COEF_32
		}
#endif
	} else {
		DES_key_schedule ks1, ks2, ks3;
		unsigned char TEMP1[sizeof(cur_salt->wrapped_hmac_sha1_key)];
		AES_KEY aes_decrypt_key;
		unsigned char outbuf[8192 + 1];
		unsigned char outbuf2[4096 + 1];
		unsigned char iv[20];
#ifdef DMG_DEBUG
		unsigned char *r;
#endif
		const char nulls[8] = { 0 };

#ifdef SIMD_COEF_32
		unsigned char *derived_key, Derived_key[SSE_GROUP_SZ_SHA1][32];
		int lens[SSE_GROUP_SZ_SHA1], i;
		unsigned char *pin[SSE_GROUP_SZ_SHA1];
		union {
			uint32_t *pout[SSE_GROUP_SZ_SHA1];
			unsigned char *poutc;
		} x;
		for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = (uint32_t*)(Derived_key[i]);
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens, cur_salt->salt, 20,
			cur_salt->iterations, &(x.poutc), 32, 0);
#else
		unsigned char derived_key[32];
		const char *password = saved_key[index];
		pbkdf2_sha1((const unsigned char*)password, strlen(password),
		       cur_salt->salt, 20, cur_salt->iterations, derived_key, 32, 0);
#endif
		j = 0;
#ifdef SIMD_COEF_32
		for (j = 0; j < SSE_GROUP_SZ_SHA1; ++j) {
		derived_key = Derived_key[j];
#endif

		DES_set_key_unchecked((DES_cblock*)(derived_key +  0), &ks1);
		DES_set_key_unchecked((DES_cblock*)(derived_key +  8), &ks2);
		DES_set_key_unchecked((DES_cblock*)(derived_key + 16), &ks3);
		memcpy(iv, cur_salt->iv, 8);
		DES_ede3_cbc_encrypt(cur_salt->encrypted_keyblob, TEMP1,
		                     cur_salt->encrypted_keyblob_size, &ks1, &ks2, &ks3,
		                     (DES_cblock*)iv, DES_DECRYPT);

		memcpy(aes_key_, TEMP1, 32);
		memcpy(hmacsha1_key_, TEMP1, 20);
		hmac_sha1(hmacsha1_key_, 20, (unsigned char*)&cur_salt->cno, 4, iv, 20);
		if (cur_salt->encrypted_keyblob_size == 48)
			AES_set_decrypt_key(aes_key_, 128, &aes_decrypt_key);
		else
			AES_set_decrypt_key(aes_key_, 128 * 2, &aes_decrypt_key);
		AES_cbc_encrypt(cur_salt->chunk, outbuf, cur_salt->data_size, &aes_decrypt_key, iv, AES_DECRYPT);

		/* 8 consecutive nulls */
		if (memmem(outbuf, cur_salt->data_size, (void*)nulls, 8)) {
#ifdef DMG_DEBUG
			if (!bench_or_test_running)
				fprintf(stderr, "NULLS found!\n\n");
#endif
			cracked[index+j] = 1;
		}

/* These tests seem to be obsoleted by the 8xNULL test */
#ifdef DMG_DEBUG
		/* </plist> is a pretty generic signature for Apple */
		if (!cracked[index+j] && memmem(outbuf, cur_salt->data_size, (void*)"</plist>", 8)) {
			if (!bench_or_test_running)
				fprintf(stderr, "</plist> found!\n\n");
			cracked[index+j] = 1;
		}

		/* Journalled HFS+ */
		if (!cracked[index+j] && memmem(outbuf, cur_salt->data_size, (void*)"jrnlhfs+", 8)) {
			if (!bench_or_test_running)
				fprintf(stderr, "jrnlhfs+ found!\n\n");
			cracked[index+j] = 1;
		}

		/* Handle compressed DMG files, CMIYC 2012 and self-made
		   samples. Is this test obsoleted by the </plist> one? */
		if (!cracked[index+j] && (r = memmem(outbuf, cur_salt->data_size, (void*)"koly", 4))) {
			unsigned int *u32Version = (unsigned int *)(r + 4);

			if (HTONL(*u32Version) == 4) {
				if (!bench_or_test_running)
					fprintf(stderr, "koly found!\n\n");
				cracked[index+j] = 1;
			}
		}

		/* Handle VileFault sample images */
		if (!cracked[index+j] && memmem(outbuf, cur_salt->data_size, (void*)"EFI PART", 8)) {
			if (!bench_or_test_running)
				fprintf(stderr, "EFI PART found!\n\n");
			cracked[index+j] = 1;
		}

		/* Apple is a good indication but it's short enough to
		   produce false positives */
		if (!cracked[index+j] && memmem(outbuf, cur_salt->data_size, (void*)"Apple", 5)) {
			if (!bench_or_test_running)
				fprintf(stderr, "Apple found!\n\n");
			cracked[index+j] = 1;
		}

#endif /* DMG_DEBUG */

		/* Second buffer test. If present, *this* is the very first block of the DMG */
		if (!cracked[index+j] && cur_salt->scp == 1) {
			int cno = 0;

			hmac_sha1(hmacsha1_key_, 20, (unsigned char*)&cno, 4, iv, 20);
			if (cur_salt->encrypted_keyblob_size == 48)
				AES_set_decrypt_key(aes_key_, 128, &aes_decrypt_key);
			else
				AES_set_decrypt_key(aes_key_, 128 * 2, &aes_decrypt_key);
			AES_cbc_encrypt(cur_salt->zchunk, outbuf2, 4096, &aes_decrypt_key, iv, AES_DECRYPT);

			/* 8 consecutive nulls */
			if (memmem(outbuf2, 4096, (void*)nulls, 8)) {
#ifdef DMG_DEBUG
				if (!bench_or_test_running)
					fprintf(stderr, "NULLS found in alternate block!\n\n");
#endif
				cracked[index+j] = 1;
			}
#ifdef DMG_DEBUG
			/* This test seem to be obsoleted by the 8xNULL test */
			if (!cracked[index+j] && memmem(outbuf2, 4096, (void*)"Press any key to reboot", 23)) {
				if (!bench_or_test_running)
					fprintf(stderr, "MS-DOS UDRW signature found in alternate block!\n\n");
				cracked[index+j] = 1;
			}
#endif /* DMG_DEBUG */
		}

#ifdef DMG_DEBUG
		/* Write block as hex, strings or raw to a file. */
		if (cracked[index+j] && !bench_or_test_running) {
#if DMG_DEBUG == 4
			const char debug_file = "dmg.debug.main";
			int fd;

			if ((fd = open(debug_file, O_RDWR | O_CREAT | O_TRUNC, 0660)) == -1)
				perror("open(%s)", debug_file);
			else
				jtr_lock(fd, F_SETLKW, F_WRLCK, debug_file);

			if ((write(fd, outbuf, cur_salt->data_size) == -1))
				perror("write()");
			if (cur_salt->scp == 1)
				if ((write(fd, outbuf2, 4096) == -1))
					perror("write()");
			if (close(fd))
				perror("close");

#endif
#if DMG_DEBUG == 3
			dump_stuff(outbuf, cur_salt->data_size);
			if (cur_salt->scp == 1) {
				fprintf(stderr, "2nd block:\n");
				dump_stuff(outbuf2, 4096);
			}
#endif
#if DMG_DEBUG == 2
			dump_text(outbuf, cur_salt->data_size);
			if (cur_salt->scp == 1) {
				fprintf(stderr, "2nd block:\n");
				dump_text(outbuf2, 4096);
			}
#endif
		}
#endif /* DMG_DEBUG */
#ifdef SIMD_COEF_32
		}
#endif
	}
	return;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
#ifdef DMG_DEBUG
	//fprintf(stderr, "Blob size is %d bytes\n", cur_salt->data_size);
#endif
}

static void dmg_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MAX_KEYS_PER_CRYPT)
	{
		hash_plugin_check_hash(index);
	}
	return count;
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

static unsigned int iteration_count(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->iterations;
}

static unsigned int headerver(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->headerver;
}

struct fmt_main fmt_dmg = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef DMG_DEBUG
		FMT_NOT_EXACT |
#endif
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
			"iteration count",
			"version",
		},
		{ FORMAT_TAG },
		dmg_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{
			iteration_count,
			headerver,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		dmg_set_key,
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

#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */
