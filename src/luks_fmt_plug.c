/*
 * This code is based on luks.c file from hashkill (a hash cracking tool)
 * project. Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>.
 *
 * This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>.
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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_luks;
#elif FMT_REGISTERS_H
john_register_one(&fmt_luks);
#else

#if AC_BUILT
#include "autoconfig.h"
#else
#define _LARGEFILE64_SOURCE 1
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> // used in this format

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "johnswap.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "memory.h"
#include "jumbo.h" // large file support
#include "os.h"
#include "aes.h"
#include "sha.h"
#include "sha2.h"
#include "base64_convert.h"
#include "pbkdf2_hmac_sha1.h"
#include "dyna_salt.h"

#define LUKS_MAGIC_L        6
#define LUKS_CIPHERNAME_L   32
#define LUKS_CIPHERMODE_L   32
#define LUKS_HASHSPEC_L     32
#define UUID_STRING_L       40
#define LUKS_DIGESTSIZE 20
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8

#define FORMAT_LABEL        "LUKS"
#define FORMAT_NAME         ""
#define FORMAT_TAG          "$luks$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)

#ifdef SIMD_COEF_32
#define ALGORITHM_NAME      "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT   ""
#define PLAINTEXT_LENGTH    125
#define BENCHMARK_LENGTH    0x107
#define BINARY_SIZE         LUKS_DIGESTSIZE
#define BINARY_ALIGN        4
#define SALT_SIZE           sizeof(struct custom_salt_LUKS*)
#define SALT_ALIGN          sizeof(struct custom_salt_LUKS*)

#ifndef OMP_SCALE
#define OMP_SCALE               1 // MKPC and scale tuned for i7
#endif

#if SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1
#endif

#include "luks_insane_tests.h"

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

static struct custom_salt_LUKS {
	dyna_salt dsalt;
	char path[8192];
	int loaded;
	struct luks_phdr myphdr;
	int afsize;
	int bestslot;
	int bestiter;
	unsigned char cipherbuf[1];
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
		IV = john_htonl(i);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, &IV, 4);
		SHA1_Update(&ctx, src + 20 * i, 20);
		SHA1_Final(dst + 20 * i, &ctx);
	}

	if (padding) {
		IV = john_htonl(fullblocks);
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

	bufblock = mem_calloc(1, blocksize + 20);

	for (i = 0; i < (stripes - 1); i++) {
		XORblock((char *) (src + (blocksize * i)), bufblock, bufblock,
		    blocksize);
		diffuse((unsigned char *) bufblock, (unsigned char *) bufblock,
		    blocksize);
	}
	XORblock((char *) (src + blocksize * (stripes - 1)), bufblock,
	    (char *) dst, blocksize);

	MEM_FREE(bufblock);
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
    unsigned char *key, int size, struct custom_salt_LUKS *cs)
{
	AES_KEY aeskey;
	unsigned char essiv[16];
	unsigned char essivhash[32];
	unsigned a;
	SHA256_CTX ctx;
	unsigned char sectorbuf[16];
	unsigned char zeroiv[16];

	// This should NEVER be done in the loop!!  This never changed.
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, key, john_ntohl(cs->myphdr.keyBytes));
	SHA256_Final(essivhash, &ctx);
	memset(sectorbuf, 0, 16);
	memset(essiv, 0, 16);

	for (a = 0; a < (size / 512); a++) {
		memset(zeroiv, 0, 16);

#if ARCH_LITTLE_ENDIAN
		memcpy(sectorbuf, &a, 4);
#else
		{ unsigned b = JOHNSWAP(a); memcpy(sectorbuf, &b, 4); }
#endif
		AES_set_encrypt_key(essivhash, 256, &aeskey);
		AES_cbc_encrypt(sectorbuf, essiv, 16, &aeskey, zeroiv, AES_ENCRYPT);
		AES_set_decrypt_key(key, john_ntohl(cs->myphdr.keyBytes)*8, &aeskey);
		AES_cbc_encrypt((src+a*512), (dst+a*512), 512, &aeskey, essiv, AES_DECRYPT);
	}
}

static int hash_plugin_parse_hash(char *filename, unsigned char **cp, int afsize, int is_critical)
{
	FILE *myfile;
	int read_entries;

	myfile = jtr_fopen(filename, "rb");

	if (!myfile) {
		fprintf(stderr, "\n%s : %s!\n", filename, strerror(errno));
		return -1;
	}

	// can this go over 4gb?
	*cp =(unsigned char*) mem_calloc(1, afsize + 1);
	if (!*cp)
		goto bad;
	// printf(">>> %d\n", cs->afsize);
	read_entries = fread(*cp, afsize, 1, myfile);

	if (read_entries != 1) {
		fprintf(stderr, "%s : unable to read required data\n",
			filename);
		goto bad;
	}
	fclose(myfile);
	return afsize+1;

bad:
	fclose(myfile);
	if (is_critical) {
		fprintf(stderr, "\nLUKS plug-in is unable to continue due to errors!\n");
		error();
	}
	return -1;
}


static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	static int warned = 0;

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);

/*
 * LUKS format will need to be redesigned to address the issues mentioned in
 * https://github.com/openwall/john/issues/557.
 * This will require a change in john's hash representation for LUKS format.
 * The redesign will happen after the next official jumbo release.
 * To avoid having to support the current LUKS hash representation forever,
 * just print a warning that the hash representation will change in future releases.
 *
 * So far, no "official" jumbo release supports the LUKS format, currently only
 * users of bleeding-jumbo may have used LUKS format. These users should be able
 * to re-run luks2john and retry the passwords that have been stored for the current LUKS hashes
 * once the redesign of john's LUKS format implementation has been completed.)
 */
	if (!options.listconf && !(options.flags & FLG_TEST_CHK) && !warned) {
		warned = 1;
		fprintf(stderr,
		        "WARNING, LUKS format hash representation will change in future releases,\n"
		        "see doc/README.LUKS\n"); // FIXME: address github issue #557 after 1.8.0-jumbo-1
		fflush(stderr);
	}

//	 This printf will 'help' debug a system that truncates that monster hash, but does not cause compiler to die.
//	printf("length=%d end=%s\n", strlen(fmt_luks.params.tests[0].ciphertext), &((fmt_luks.params.tests[0].ciphertext)[strlen(fmt_luks.params.tests[0].ciphertext)-30]));
#ifdef _MSC_VER
	LUKS_test_fixup();
#endif
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p, *q;
	unsigned char *buf = 0;
	int is_inlined, i, bestslot = -1;
	int hdr_size;
	int afsize;
	unsigned char *out;
	struct custom_salt_LUKS cs;
	uint64_t keybytes, stripes;
	unsigned int bestiter = 0xFFFFFFFF;
	size_t len, len_b64;

	out = (unsigned char*)&cs.myphdr;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* is_inlined */
		goto err;
	if (!isdec(p))
		goto err;
	is_inlined = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (!isdec(p))
		goto err;
	hdr_size = atoi(p);
	if (hdr_size != sizeof(struct luks_phdr))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (hdr_size != strlen(p) / 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	for (i = 0; i < hdr_size; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	keybytes = john_ntohl(cs.myphdr.keyBytes);
	if (keybytes > 256) /* bigger requires more space in keycandidate */
		goto err;
	for (i = 0; i < LUKS_NUMKEYS; i++) {
			if ((john_ntohl(cs.myphdr.keyblock[i].passwordIterations) < bestiter)
			&& (john_ntohl(cs.myphdr.keyblock[i].passwordIterations) > 1) &&
			(john_ntohl(cs.myphdr.keyblock[i].active) == 0x00ac71f3)) {
				bestslot = i;
				bestiter =
				john_ntohl(cs.myphdr.keyblock[i].passwordIterations);
			}
	}
	if (bestslot < 0) /* active key is not found */
		goto err;
	if (bestiter >= INT_MAX) /* artificial, to fit in int, plus 1 special value */
		goto err;
	stripes = john_ntohl(cs.myphdr.keyblock[bestslot].stripes);
	if (stripes == 0) /* we use it for division */
		goto err;
	if ((uint32_t)keybytes * (uint32_t)stripes != keybytes*stripes)
		goto err;
	if (stripes > INT_MAX || keybytes > INT_MAX) /* artificial, to allow int */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (!isdec(p))
		goto err;
	afsize = atoi(p);
	if (afsize != keybytes*stripes)
		goto err;
	if (afsize % 512 != 0) /* incomplete sectors are not implemented */
		goto err;
	/* 'afsize % 512 == 0' implies that 'afsize <= INT_MAX - 20', that's good against wrapping of integers. */

	if (is_inlined) {
		if ((p = strtokm(NULL, "$")) == NULL)	/* dump data */
			goto err;
		len = ((size_t)afsize + 2) / 3 * 4;
		if (len != strlen(p))
			goto err;
		/* check base64 and precise number of trailing = */
		len_b64 = base64_valid_length(p, e_b64_mime, flg_Base64_NO_FLAGS, 0);
		switch (len - len_b64) {
		case 0: /* BBB <-> AAAA */
			if (afsize % 3 != 0)
				goto err;
			break;
		case 1: /* BB  <-> AAA= */
			if (afsize % 3 != 2 || p[len - 1] != '=')
				goto err;
			break;
		case 2: /* B   <-> AA==  */
			if (afsize % 3 != 1 || p[len - 1] != '=' || p[len - 2] != '=')
				goto err;
			break;
		default:
			goto err;
		}
		if ((p = strtokm(NULL, "$")) == NULL)	/* mkDigest */
			goto err;
		if (strlen(p) != LUKS_DIGESTSIZE * 2)
			goto err;
		if (!ishexlc(p))
			goto err;
	}
	else {
		if ((p = strtokm(NULL, "$")) == NULL)	/* LUKS file */
			goto err;
		if ((p = strtokm(NULL, "$")) == NULL)	/* dump file */
			goto err;
		q = p;
		if ((p = strtokm(NULL, "$")) == NULL)	/* mkDigest */
			goto err;
		if (strlen(p) != LUKS_DIGESTSIZE * 2)
			goto err;
		if (!ishexlc(p))
			goto err;

		/* more tests */
		if (hash_plugin_parse_hash(q, &buf, afsize, 0) == -1) {
			goto err;
		}
	}
	if (strtokm(NULL, "$")) /* no more fields */
		goto err;

	MEM_FREE(buf);
	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(buf);
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int is_inlined;
	int res;
	int i;
	int cnt;
	unsigned char *out;
	unsigned char *buf;
	struct custom_salt_LUKS cs, *psalt;
	static unsigned char *ptr;
	size_t size = 0;

	ctcopy += FORMAT_TAG_LEN;


	if (!ptr) ptr = mem_alloc_tiny(sizeof(struct custom_salt*),sizeof(struct custom_salt*));
	memset(&cs, 0, sizeof(cs));
	cs.bestiter = INT_MAX;
	out = (unsigned char*)&cs.myphdr;

	p = strtokm(ctcopy, "$");
	is_inlined = atoi(p);

	/* common handling */
	p = strtokm(NULL, "$");
	res = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < res; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	p = strtokm(NULL, "$");
	cs.afsize = atoi(p);

	if (is_inlined) {
		p = strtokm(NULL, "$");
		size = strlen(p) / 4 * 3 + 1;
		buf = mem_calloc(1, size+4);
		base64_convert(p, e_b64_mime, strlen(p), buf, e_b64_raw, size+4, flg_Base64_NO_FLAGS, 0);
	}
	else {
		p = strtokm(NULL, "$");
		p = strtokm(NULL, "$");
		strcpy(cs.path, p);
		size = hash_plugin_parse_hash(cs.path, &buf, cs.afsize, 1);
	}
	for (cnt = 0; cnt < LUKS_NUMKEYS; cnt++) {
			if ((john_ntohl(cs.myphdr.keyblock[cnt].passwordIterations) < cs.bestiter)
			&& (john_ntohl(cs.myphdr.keyblock[cnt].passwordIterations) > 1) &&
			(john_ntohl(cs.myphdr.keyblock[cnt].active) == 0x00ac71f3)) {
				cs.bestslot = cnt;
				cs.bestiter =
				john_ntohl(cs.myphdr.keyblock[cnt].passwordIterations);
			}
	}
	cs.afsize = af_sectors(john_ntohl(cs.myphdr.keyBytes),
			john_ntohl(cs.myphdr.keyblock[cs.bestslot].stripes));
	MEM_FREE(keeptr);

	psalt = (struct custom_salt_LUKS*)mem_alloc_tiny(sizeof(struct custom_salt_LUKS)+size, 4);
	memcpy(psalt, &cs, sizeof(cs));
	memcpy(psalt->cipherbuf, buf, size);
	MEM_FREE(buf);
	psalt->dsalt.salt_alloc_needs_free = 0;

	// set the JtR core linkage stuff for this dyna_salt
	psalt->dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt_LUKS, myphdr);
	psalt->dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt_LUKS, myphdr, cipherbuf, size);

	memcpy(ptr, &psalt, sizeof(struct custom_salt*));
	return (void*)ptr;
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

static void set_salt(void *salt)
{
	cur_salt = *(struct custom_salt_LUKS **)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
		unsigned char *af_decrypted = (unsigned char *)mem_alloc(cur_salt->afsize + 20);
		int i, iterations = cur_salt->bestiter;
		int dklen = john_ntohl(cur_salt->myphdr.keyBytes);
		uint32_t keycandidate[MIN_KEYS_PER_CRYPT][256/4];
		uint32_t masterkeycandidate[MIN_KEYS_PER_CRYPT][256/4];
#ifdef SIMD_COEF_32
		int lens[MIN_KEYS_PER_CRYPT];
		unsigned char *pin[MIN_KEYS_PER_CRYPT];
		union {
			uint32_t *pout[MIN_KEYS_PER_CRYPT];
			unsigned char *poutc;
		} x;

		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = strlen(saved_key[index+i]);
			pin[i] = (unsigned char*)saved_key[index+i];
			x.pout[i] = keycandidate[i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens,
		                (const unsigned char*)(cur_salt->myphdr.keyblock[cur_salt->bestslot].passwordSalt), LUKS_SALTSIZE,
		                iterations, &(x.poutc),
		                dklen, 0);
#else
		pbkdf2_sha1((const unsigned char *)saved_key[index], strlen(saved_key[index]),
		            (const unsigned char*)(cur_salt->myphdr.keyblock[cur_salt->bestslot].passwordSalt), LUKS_SALTSIZE,
		            iterations, (unsigned char*)keycandidate[0], dklen, 0);
#endif
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			// Decrypt the blocksi
			decrypt_aes_cbc_essiv(cur_salt->cipherbuf, af_decrypted, (unsigned char*)keycandidate[i], cur_salt->afsize, cur_salt);
			// AFMerge the blocks
			AF_merge(af_decrypted, (unsigned char*)masterkeycandidate[i], cur_salt->afsize,
			         john_ntohl(cur_salt->myphdr.keyblock[cur_salt->bestslot].stripes));
		}
		// pbkdf2 again
#ifdef SIMD_COEF_32
		for (i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
			lens[i] = john_ntohl(cur_salt->myphdr.keyBytes);
			pin[i] = (unsigned char*)masterkeycandidate[i];
			x.pout[i] = crypt_out[index+i];
		}
		pbkdf2_sha1_sse((const unsigned char **)pin, lens,
		                (const unsigned char*)cur_salt->myphdr.mkDigestSalt, LUKS_SALTSIZE,
		                john_ntohl(cur_salt->myphdr.mkDigestIterations), &(x.poutc),
		                LUKS_DIGESTSIZE, 0);
#else
		pbkdf2_sha1((unsigned char*)masterkeycandidate[0], john_ntohl(cur_salt->myphdr.keyBytes),
		            (const unsigned char*)cur_salt->myphdr.mkDigestSalt, LUKS_SALTSIZE,
		            john_ntohl(cur_salt->myphdr.mkDigestIterations),
		            (unsigned char*)crypt_out[index], LUKS_DIGESTSIZE, 0);

#endif
		MEM_FREE(af_decrypted);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
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
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
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
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_DYNA_SALT | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		luks_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_dyna_salt_hash,
		NULL,
		set_salt,
		luks_set_key,
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
