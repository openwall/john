/* luks.c
 *
 * hashkill - a hash cracking tool
 * Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>
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
 */

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <string.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "gladman_pwd2key.h"
#ifdef _OPENMP
static int omp_t = 1;
#include <omp.h>
#define OMP_SCALE               1
#endif

#define LUKS_MAGIC_L        6
#define LUKS_CIPHERNAME_L   32
#define LUKS_CIPHERMODE_L   32
#define LUKS_HASHSPEC_L     32
#define UUID_STRING_L       40
#define LUKS_DIGESTSIZE 20
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8

#define FORMAT_LABEL		"luks"
#define FORMAT_NAME		"LUKS"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define PLAINTEXT_LENGTH  	125
#define BENCHMARK_LENGTH	-1
#define BINARY_SIZE		LUKS_DIGESTSIZE
#define SALT_SIZE		sizeof(struct custom_salt)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1

#define htonl(x) ((((x)>>24) & 0xffL) | (((x)>>8) & 0xff00L) | \
		(((x)<<8) & 0xff0000L) | (((x)<<24) & 0xff000000L))

#define ntohl(x) ((((x)>>24) & 0xffL) | (((x)>>8) & 0xff00L) | \
		(((x)<<8) & 0xff0000L) | (((x)<<24) & 0xff000000L))

static struct fmt_tests luks_tests[] = {
	{"$luks$/home/dkholia/LUKS-openwall$8bfd2b083d5b0fa82c5e00d099fe7b0d516ed90a", "openwall"},
	{NULL}
};

/* taken from LUKS on disk format specification */
struct luks_phdr {
	char magic[LUKS_MAGIC_L];
	uint16_t version;
	char cipherName[LUKS_CIPHERNAME_L];
	char cipherMode[LUKS_CIPHERMODE_L];
	char hashSpec[LUKS_HASHSPEC_L];
	uint32_t payloadOffset;
	uint32_t keyBytes;
	char mkDigest[LUKS_DIGESTSIZE];
	char mkDigestSalt[LUKS_SALTSIZE];
	uint32_t mkDigestIterations;
	char uuid[UUID_STRING_L];
	struct {
		uint32_t active;
		uint32_t passwordIterations;
		char passwordSalt[LUKS_SALTSIZE];
		uint32_t keyMaterialOffset;
		uint32_t stripes;
	} keyblock[LUKS_NUMKEYS];
};

static struct custom_salt {
	struct luks_phdr myphdr;
	int loaded;
	unsigned char *cipherbuf;
	int afsize;
	int bestslot;
	char path[8192];
} *cur_salt;

static void XORblock(char *src1, char *src2, char *dst, int n)
{
	int j;

	for (j = 0; j < n; j++)
		dst[j] = src1[j] ^ src2[j];
}

static int diffuse(unsigned char *src, unsigned char *dst, int size)
{
	uint32_t i;
	uint32_t IV;		/* host byte order independent hash IV */
	SHA_CTX ctx;
	int fullblocks = (size) / 20;
	int padding = size % 20;

	for (i = 0; i < fullblocks; i++) {
		IV = htonl(i);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, &IV, 4);
		SHA1_Update(&ctx, src + 20 * i, 20);
		SHA1_Final(dst + 20 * i, &ctx);
	}

	if (padding) {
		IV = htonl(fullblocks);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, &IV, 4);
		SHA1_Update(&ctx, src + 20 * fullblocks, padding);
		SHA1_Final(dst + 20 * fullblocks, &ctx);
	}
	return 0;
}

static int AF_merge(unsigned char *src, unsigned char *dst, int afsize,
    int stripes)
{
	int i;
	char *bufblock;
	int blocksize = afsize / stripes;

	bufblock = alloca(blocksize);

	memset(bufblock, 0, blocksize);
	for (i = 0; i < (stripes - 1); i++) {
		XORblock((char *) (src + (blocksize * i)), bufblock, bufblock,
		    blocksize);
		diffuse((unsigned char *) bufblock, (unsigned char *) bufblock,
		    blocksize);
	}
	XORblock((char *) (src + blocksize * (stripes - 1)), bufblock,
	    (char *) dst, blocksize);
	return 0;
}

static int af_sectors(int blocksize, int blocknumbers)
{
	int af_size;

	af_size = blocksize * blocknumbers;
	af_size = (af_size + 511) / 512;
	af_size *= 512;
	return af_size;
}


static void decrypt_aes_cbc_essiv(unsigned char *src, unsigned char *dst,
    unsigned char *key, int startsector, int size, struct custom_salt *cs)
{
	AES_KEY aeskey;
	unsigned char essiv[16];
	unsigned char essivhash[32];
	int a;
	SHA256_CTX ctx;
	unsigned char sectorbuf[16];
	unsigned char zeroiv[16];

	for (a = 0; a < (size / 512); a++) {
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, ntohl(cs->myphdr.keyBytes));
		SHA256_Final(essivhash, &ctx);
		bzero(sectorbuf, 16);
		bzero(zeroiv, 16);
		bzero(essiv, 16);
		memcpy(sectorbuf, &a, 4);
		AES_set_encrypt_key(essivhash, 256, &aeskey);
		AES_cbc_encrypt(sectorbuf, essiv, 16, &aeskey, zeroiv, AES_ENCRYPT);
		AES_set_decrypt_key(key, ntohl(cs->myphdr.keyBytes)*8, &aeskey);
		AES_cbc_encrypt((src+a*512), (dst+a*512), 512, &aeskey, essiv, AES_DECRYPT);
	}
}

static int hash_plugin_parse_hash(char *filename, struct custom_salt *cs)
{
	FILE *myfile;
	int cnt;
	int readbytes;
	unsigned int bestiter = 0xFFFFFFFF;

	myfile = fopen(filename, "rb");

	if (fread(&(cs->myphdr), sizeof(struct luks_phdr), 1, myfile) < 1) {
		puts("file opening problem!");
	}

	if (strcmp(cs->myphdr.magic, "LUKS\xba\xbe") != 0) {
		puts("not a LUKS file");
	}

	if (strcmp(cs->myphdr.cipherName, "aes") != 0) {
		printf("Only AES cipher supported. Used cipher: %s\n",
		    cs->myphdr.cipherName);
	}

	for (cnt = 0; cnt < LUKS_NUMKEYS; cnt++) {
		if ((ntohl(cs->myphdr.keyblock[cnt].passwordIterations) < bestiter)
		    && (ntohl(cs->myphdr.keyblock[cnt].passwordIterations) > 1) &&
		    (ntohl(cs->myphdr.keyblock[cnt].active) == 0x00ac71f3)) {
			cs->bestslot = cnt;
			bestiter =
			    ntohl(cs->myphdr.keyblock[cnt].passwordIterations);
		}
	}
	if (cs->bestslot == 2000)
		goto bad;

	cs->afsize =
	    af_sectors(ntohl(cs->myphdr.keyBytes),
	    ntohl(cs->myphdr.keyblock[cs->bestslot].stripes));
	cs->cipherbuf = malloc(cs->afsize); // XXX handle this leak
	fseek(myfile, ntohl(cs->myphdr.keyblock[cs->bestslot].keyMaterialOffset) * 512,
	    SEEK_SET);
	readbytes = fread(cs->cipherbuf, cs->afsize, 1, myfile);

	if (readbytes < 0) {
		free(cs->cipherbuf);
		fclose(myfile);
	}
	// printf("Best keyslot [%d]: %d keyslot iterations, %d stripes, %d mkiterations\n", cs->bestslot, ntohl(cs->myphdr.keyblock[cs->bestslot].passwordIterations),ntohl(cs->myphdr.keyblock[cs->bestslot].stripes),ntohl(cs->myphdr.mkDigestIterations));

	return 0;
bad:
	return 1;
}


static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

// XXX implement a robust validator
static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, "$luks$", 6) != 0)
		return 0;
	return 1;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	ctcopy += 6;

	p = strtok(ctcopy, "$");
	strcpy(cs.path, p);
	hash_plugin_parse_hash(cs.path, &cs);
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[LUKS_DIGESTSIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < LUKS_DIGESTSIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		unsigned char keycandidate[255];
		unsigned char masterkeycandidate[255];
		unsigned char *af_decrypted = alloca(cur_salt->afsize); // XXX remove alloca
		char *password = saved_key[index];
		int iterations = ntohl(cur_salt->myphdr.keyblock[cur_salt->bestslot].passwordIterations);

		int dklen = ntohl(cur_salt->myphdr.keyBytes);

		// Get pbkdf2 of the password to obtain decryption key
		derive_key((const uint8_t*)password, strlen(password),
			(const uint8_t*)(cur_salt->myphdr.keyblock[cur_salt->bestslot].passwordSalt),
			LUKS_SALTSIZE,
			iterations,
			keycandidate,
			dklen);

		// Decrypt the blocksi
		decrypt_aes_cbc_essiv(cur_salt->cipherbuf, af_decrypted, keycandidate,
		ntohl(cur_salt->myphdr.keyblock[cur_salt->bestslot].keyMaterialOffset), cur_salt->afsize, cur_salt);
		// AFMerge the blocks
		AF_merge(af_decrypted, masterkeycandidate, cur_salt->afsize,
		ntohl(cur_salt->myphdr.keyblock[cur_salt->bestslot].stripes));
		// pbkdf2 again
		derive_key(masterkeycandidate,
			ntohl(cur_salt->myphdr.keyBytes),
			(const uint8_t*)cur_salt->myphdr.mkDigestSalt,
			LUKS_SALTSIZE,
			ntohl(cur_salt->myphdr.mkDigestIterations),
			(unsigned char*)crypt_out[index],
			LUKS_DIGESTSIZE);

	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (!memcmp(binary, crypt_out[index], LUKS_DIGESTSIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], LUKS_DIGESTSIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void luks_set_key(char *key, int index)
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

struct fmt_main fmt_luks = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		DEFAULT_ALIGN,
		SALT_SIZE,
		DEFAULT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		luks_tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		luks_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
