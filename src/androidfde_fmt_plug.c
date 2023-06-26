/*
 * This code is based on androidfde.c file from hashkill (a hash cracking tool)
 * project. Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>.
 *
 * Modified for JtR and made stuff more generic - Dhiru.
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
extern struct fmt_main fmt_fde;
#elif FMT_REGISTERS_H
john_register_one(&fmt_fde);
#else

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

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
#include "pbkdf2_hmac_sha1.h"
#include "aes.h"
#include "sha2.h"

#define FORMAT_TAG          "$fde$"
#define TAG_LENGTH          (sizeof(FORMAT_TAG)-1)
#define FORMAT_LABEL        "fde"
#define FORMAT_NAME         "Android FDE"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME      "PBKDF2-SHA1 " SHA1_ALGORITHM_NAME " SHA256/AES"
#else
#define ALGORITHM_NAME      "PBKDF2-SHA1 SHA256/AES 32/" ARCH_BITS_STR
#endif
#define BENCHMARK_COMMENT   ""
#define PLAINTEXT_LENGTH    64
#define BENCHMARK_LENGTH    0x107
#define BINARY_SIZE         0
#define BINARY_ALIGN        1
#define SALT_SIZE           sizeof(struct custom_salt)
#define SALT_ALIGN          sizeof(void*)
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  SSE_GROUP_SZ_SHA1
#define MAX_KEYS_PER_CRYPT  (SSE_GROUP_SZ_SHA1 * 4)
#else
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  4
#endif

#ifndef OMP_SCALE
#define OMP_SCALE           16 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests fde_tests[] = {
	{"$fde$16$04b36d4290b56e0fcca9778b74719ab8$16$b45f0f051f13f84872d1ef1abe0ada59$0f61d28f7466c0435040cc845a67e6734500de15df3ba6f48d2534ca2a7b8f910d7547357e8f1ec7364bab41383f5df9b5fb43fcd4a1e06189ce3c6ba77ec908b066e73a508e201c941fb409e9abdc051c3c052a735b01e56be61efa635e82cbceab18db1ba645b93f7befb83155852f0004a7c7d6800e9fa5f0d3c133dd2496f92110c3cdcfb16dcf57df8de830969e18514a34d4917de14597da19f9f7dc81eca2d7d461c91e0a8aeac06bafe89866d24f2b4991b4295b6277d0ff4ad97f1fa58e20f8a24e2062f84c318eb36cfbb4671117bc3522afcf7737353589cae0dce0d7c3341f457af654543758f3f005bd4d68fa2b35777cb2ea5f8f69c4debcfb1d8b2a601320e4f8621dc6e99434007388bdc0ceebc722f9ed44cbce3914bf144db332276e719f6b48108cde55916d861d19dc8c03ac76a2dad322457073111e441488228f13649073aa3aadfab51dadf89a0827acba284154a9e18d926facef43852a0733660a1fbcca8e81d2f41efd9f645a61f9395b75fc7ad446885d304808d511f2ba2e7c6138588c4292aee4ef6f2537bb00c7b015cee4a91d2defa87b67abc1315e71f0489e271673b36412377219e93aba6af3cfd504bf3f6bc24f2b6148536339d91ddd2f013314544650c1c11e7317028a7014909d0c850f78692e476c4f57da586fe26786504130aba22ba5261b989aeb47483d8cb9d5052120a4e5690b5b0cd009aadaadc351db7b6a230ebc1fa771651cb64d78daa56b7a6c6808db3b688afee9b7edaa617d8cb16ac7290465987bd443ea41ce38aa14e0c88874fb2707394b83679de82134efe351b4d021c63b2992a8314b2e93908906400628a7f753c9a4d85e917a207561b7840ce121800fab4026508d1b00fe8e7e756573743e11380f76f6bb7c0e528cb98875e6ad88bff51236601e6942964e37ffe0316b1a1f7bc0d84334fa024bf03c261bd06a07c01f099ad23fb9a1d8c98447463b8988cb33f3e1fb7d7a7c547f9a6d51cf7b75649d3c8cb5bf93be79eba1a961659b5fe928a1c7e80aca857825c6bc11493cb230e66126ef7b7284abe0823b5735bb1dfe844029f175c63442ca774784b775ecf02e48d029ac0f236813be91aca66905640666b89bd08118e3c18c75764bc49d00d1fe53ee92ccaa487852c613cba91f637b6de06dcaa1953a7cfb5333df573273a67f0157b63fbbf48c48f16c423caefaf29cdb5d34b19ac0f57b972b9e5ff1bc5cf25bdcdf8d29fb75865c4501458f19bfd64c844fd52a27feec97dc31ba922aea75706404d853071707d0c6001c59664676be6426ca5c7efbfc09ffa9acac91441f9175fd3148fb046c31a49d7c7ad10bf3c4b413dd148666b72b5a533f600cb02d7623270e5d1ad33355dd318d06aa8b3d7517cb7d5be40d222a026380cfbf5b79014e7631d677b07bcd805d9ea7103cf1d057bf883b29fb99b064c4e3cb4271596a74895c1c3f7c7c49d2be54b1435af4440ecd019dde11cee14a320712c9275bef339a15d3a18d9f38918d7af0a50a35199980429d74d4cc2a16dea619619a7c19827f4f78d3ebaf13340abf6717cec6bff8399b067fb17f11cdb1f9909c51253f7466ee769546d1d96319bcc1b04a6b1f8d8068f96b959d507c9004d75717792733fadb7a94a2d5db514a61cbd90eef89d1ace5a3138120168d62f1ebef5efbbd4e7f7e987834db81fe8c4877f3edcc71c61e96b20ca26c5a91e28fa11e484c1dcbfd5a0461065fe52f042ee9a09687d800c90a0a792f3dbe257965247f8eecd122b9b234b734454fa1477212a0295a347ae44463de4de405bf4fd91cde400b63d7fced6d7ccd20d79a4899139a79085f8742c3dfe7fbadca56c4e8aa95ce7841ad9675659349f6671d047efa0951feb9c61381f5f9e39182c1ec0a3ebd2ef5e036312c6ed6a0e59777813229ffdac771788e609c7d9f96848f63b428789c55e85c509068df8d5a0a7fc066be8c76205860d86d6c5bb7c2bc85a922a2ad86e6a791fe238420eedd1cf7ac770dd8316ca30c9577441a34873cdf0c5dc2103457a93fa0dd42da5eb2d6f82e9ff47b4bb6cd1d3fcba5645caace577a89c7bd70ff432f8dae113a7877a41a41043dac4c0d21860ad8198a1b9640d979322a20d4b90caa77a5d2b31c5bd06e", "strongpassword"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int max_cracked;

static struct custom_salt {
	unsigned char *cipherbuf;
	int loaded;
	int keysize;
	int iterations; // NOTE, not used. Hard coded to 2000 for FDE from Android <= 4.3 (PBKDF2-SHA1)
	int saltlen;
	unsigned char data[512 * 3];
	unsigned char salt[16];
	unsigned char mkey[64];
	unsigned char iv[16];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	max_cracked = self->params.max_keys_per_crypt;
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	cracked   = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	int saltlen, keysize, extra;
	char *p;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (!isdec(p))
		goto err;
	saltlen = atoi(p);
	if (saltlen > 16)			/* saltlen */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != saltlen * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* keysize */
		goto err;
	if (!isdec(p))
		goto err;
	keysize = atoi(p);
	if (keysize > 64)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* key */
		goto err;
	if (hexlenl(p, &extra) != keysize * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)	/* data */
		goto err;
	if (hexlenl(p, &extra) != 512 * 3 * 2 || extra)
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
	char *p;
	int i;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.saltlen; i++) {
		cs.salt[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	p = strtokm(NULL, "$");
	cs.keysize = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.keysize; i++) {
		cs.mkey[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	p = strtokm(NULL, "$");
	for (i = 0; i < 512 * 3; i++) {
		cs.data[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

// Not reference implementation - this is modified for use by androidfde!
static void AES_cbc_essiv(unsigned char *src, unsigned char *dst, unsigned char *key, int startsector, int size)
{
	AES_KEY aeskey;
	unsigned char essiv[16];
	unsigned char essivhash[32];
	SHA256_CTX ctx;
	unsigned char sectorbuf[16];
	unsigned char zeroiv[16];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, key, cur_salt->keysize);
	SHA256_Final(essivhash, &ctx);
	memset(sectorbuf, 0, 16);
	memset(zeroiv, 0, 16);
	memset(essiv, 0, 16);
	memcpy(sectorbuf, &startsector, 4);
	AES_set_encrypt_key(essivhash, 256, &aeskey);
	AES_cbc_encrypt(sectorbuf, essiv, 16, &aeskey, zeroiv, AES_ENCRYPT);
	AES_set_decrypt_key(key, cur_salt->keysize * 8, &aeskey);
	AES_cbc_encrypt(src, dst, size, &aeskey, essiv, AES_DECRYPT);
}

void hash_plugin_check_hash(int index)
{
	unsigned char keycandidate2[255];
	unsigned char decrypted1[512]; // FAT
	unsigned char decrypted2[512]; // ext3/4
	AES_KEY aeskey;
	uint16_t v2,v3,v4;
	uint32_t v1,v5;
	int j = 0;

#ifdef SIMD_COEF_32
	unsigned char *keycandidate, Keycandidate[SSE_GROUP_SZ_SHA1][255];
	int lens[SSE_GROUP_SZ_SHA1], i;
	unsigned char *pin[SSE_GROUP_SZ_SHA1];
	union {
		uint32_t *pout[SSE_GROUP_SZ_SHA1];
		unsigned char *poutc;
	} x;
	for (i = 0; i < SSE_GROUP_SZ_SHA1; ++i) {
		lens[i] = strlen(saved_key[index+i]);
		pin[i] = (unsigned char*)saved_key[index+i];
		x.pout[i] = (uint32_t*)(Keycandidate[i]);
	}
	pbkdf2_sha1_sse((const unsigned char **)pin, lens, cur_salt->salt, 16,
		2000, &(x.poutc), cur_salt->keysize + 16, 0);
#else
	unsigned char keycandidate[255];
	char *password = saved_key[index];
	pbkdf2_sha1((const uint8_t*)password, strlen(password), (const uint8_t*)(cur_salt->salt),
		16, 2000, keycandidate, cur_salt->keysize + 16, 0);
#endif
	j = 0;
#ifdef SIMD_COEF_32
	for (; j < SSE_GROUP_SZ_SHA1; ++j) {
	keycandidate = Keycandidate[j];
#endif
	AES_set_decrypt_key(keycandidate, cur_salt->keysize*8, &aeskey);
	AES_cbc_encrypt(cur_salt->mkey, keycandidate2, 16, &aeskey, keycandidate+16, AES_DECRYPT);
	AES_cbc_essiv(cur_salt->data, decrypted1, keycandidate2, 0, 32);
	AES_cbc_essiv(cur_salt->data + 1024, decrypted2, keycandidate2, 2, 128);

	// Check for FAT
	if (!memcmp(decrypted1 + 3, "MSDOS5.0", 8))
	    cracked[index+j] = 1;
	else {
		// Check for extfs
		memcpy(&v1, decrypted2+72, 4);
		memcpy(&v2, decrypted2+0x3a, 2);
		memcpy(&v3, decrypted2+0x3c, 2);
		memcpy(&v4, decrypted2+0x4c, 2);
		memcpy(&v5, decrypted2+0x48, 4);
#if !ARCH_LITTLE_ENDIAN
		v1 = JOHNSWAP(v1);
		v2 = JOHNSWAP(v2);
		v3 = JOHNSWAP(v3);
		v4 = JOHNSWAP(v4);
		v5 = JOHNSWAP(v5);
#endif
		if ((v1<5)&&(v2<4)&&(v3<5)&&(v4<2)&&(v5<5))
			cracked[index+j] = 1;
	}
#ifdef SIMD_COEF_32
	}
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	memset(cracked, 0, sizeof(cracked[0])*max_cracked);
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
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

static void fde_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_fde = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		fde_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		fde_set_key,
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
