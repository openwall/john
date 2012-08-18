/* PuTTY private key cracker patch for JtR. Hacked together during Monsoon of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 *
 * p-ppk-crack v0.5 made by michu@neophob.com — PuTTY private key cracker
 *
 * Source code based on putty svn version, check
 * http://chiark.greenend.org.uk/~sgtatham/putty/licence.html. */

#include <string.h>
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
//#include <openssl/hmac.h>
#include "gladman_hmac.h"
#include <openssl/aes.h>
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif

#define FORMAT_LABEL        "putty"
#define FORMAT_NAME         "PuTTY Private Key SHA-1 / AES"
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

#define PUT_32BIT_MSB_FIRST(cp, value) ( \
		(cp)[0] = (unsigned char)((value) >> 24), \
		(cp)[1] = (unsigned char)((value) >> 16), \
		(cp)[2] = (unsigned char)((value) >> 8), \
		(cp)[3] = (unsigned char)(value) )

#define PUT_32BIT(cp, value) PUT_32BIT_MSB_FIRST(cp, value)


static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked;
static int any_cracked;
static size_t cracked_size;

static struct custom_salt {
	int is_mac, old_fmt;
	char alg[8];
	int cipher, cipherblk;
	int public_blob_len, private_blob_len;
	char encryption[32];
	char mac[128];
	char comment[512];
	unsigned char public_blob[4096];
	unsigned char private_blob[4096];
} *cur_salt;

static struct fmt_tests putty_tests[] = {
	{"$putty$1*16*1*0*10c434c33cf160352b7a5b3a1ecd8434f1066cac*432*000000077373682d647373000000806bb7ed4d03163f5be550dba68e0f1af7dae4b49f736ab452552a1163210c1366fd1f65a31bb526b1d3028a31d30b3315c19dc02417db99336f00b1f9565431d02fc59cd756ab6fe506b959df3799e4a70fcbe54ad9ef34d338014add8ac1f57f2a6dce8403c93709cb23d3c379f5de4f9fc45a73b3f9a43e6c1cc220bd38274b0000001500b4bf70cda203027a13135d43e459872eed384a3d0000008049a7d8e8d1db1630f9a9f6b1bf275d01e4287a4c2f038707d8c07ab664dbd264f6b4676de93c1f003bb57146a82314ab6c426628498209fa33c68a881abfd90dc1e978d430c9ace78d6c9895938494e91e3ca50132c9bde8fae4381e6fe59d03a9feee39b10cb2fea4e4d5f5ef10e523d34925f105eff665db2ac35e6cf0a1ac000000800def6e4f7ed4af0f1f8ed9524595d3fecd0a191ea9a6402d4235ee59ff2000011e36b5936280a3b5dc0b8d8ea7747e04ad92e46be8cb374d931c1e78bbdafea4ac16aba2e4b3cbd0779d28a609e848fb54332a169f24fac5e4c736c3dae4f95afe0aacaffb2d4829956fbd17d514614a45f8eefdd0d7d4982d101d72002f05fd*32*b38180c482949f3b4f44a20fd599c2cb411c671b4b120663bef9a61b360e442a*ssh-dss*aes256-cbc*dsa-key-20120721", "password"},
	{"$putty$1*16*1*0*0dbfd7b4ec870df2fb8becc9efa6feeec683cd98*149*000000077373682d727361000000012500000081008ffc01db52ff6543a67b747e9882d04c32dc769b0b1fa575e1e838133d0bc381291af654b112a6ead07b157e5556d2052c7d516b605415687769f1095e2107067e08cc569e6382b31a42d93bbb4c189c01469872b65e50af3f81ed651cb4144c556cadefda8706f00c65699a074fc4fa5843a8370852d04b8f5575f0f2186611*352*9df7f3992f46922e9e03ee381a9ba06082fcf07f572f5a742400fdbdb8fd850161b0dd877ce1fb5433311c097463a8b0c0d7e98f58d361ca1579a01d30878c8b934653ee1278942ee1fbba092e495d2c8b2f5903b7cb3fd1b5c0445d993e3139fa3741dd51e968fb8cc9cc5c257d25cb94d404e448ec334fc1be713c3156a8c9110280623687a7f3c5a8dede7efa98d4bfd12ae8cef634c0c51dcdccf2a9f65e14bd3f5cb34270ad1ea02732d653073fc2e772e3dfea14fa29a50052831bafedd10bd73a13c52db956e2b674115d9620cc1136432edc4e2968681d177278999cda7cc6aeb9e2427a11f2aee67990c02a400144fab0cf4546d19726247a076423384bd98c3d6fb810ab5ee7ff248b8a87a6652dff7deb38349b9929ba29375dcdd90c7e01ad6900b48cf48300dd157cc80ae94a1d6e7545ec7fcaf96e0172acf08ee7e21e494ca601f5890ad9e8ca5ff89141aa50ae188842da52ae000d38d1fa*ssh-rsa*aes256-cbc*rsa-key-20120721", "openwall"},
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
	return !strncmp(ciphertext, "$putty$", 7);
}

static void *get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;
	ctcopy += 7;	/* skip over "$putty$" marker */
	p = strtok(ctcopy, "*");
	cs.cipher = atoi(p);
	p = strtok(NULL, "*");
	cs.cipherblk = atoi(p);
	p = strtok(NULL, "*");
	cs.is_mac = atoi(p);
	p = strtok(NULL, "*");
	cs.old_fmt = atoi(p);
	p = strtok(NULL, "*");
	strcpy(cs.mac, p);
	p = strtok(NULL, "*");
	cs.public_blob_len = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.public_blob_len; i++)
		cs.public_blob[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtok(NULL, "*");
	cs.private_blob_len = atoi(p);
	p = strtok(NULL, "*");
	for (i = 0; i < cs.private_blob_len; i++)
		cs.private_blob[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	if(!cs.old_fmt) {
		p = strtok(NULL, "*");
		strcpy(cs.alg, p);
		p = strtok(NULL, "*");
		strcpy(cs.encryption, p);
		p = strtok(NULL, "*");
		strcpy(cs.comment, p);
	}
	MEM_FREE(keeptr);
	return (void *)&cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}
}

static void putty_set_key(char *key, int index)
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

static void SHA_Simple(void *p, int len, unsigned char *output)
{
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, p, len);
	SHA1_Final(output, &ctx);
}

static int LAME_ssh2_load_userkey(char *passphrase)
{
	int passlen = strlen(passphrase);
	unsigned char *out = alloca(cur_salt->private_blob_len);
	AES_KEY akey;
	unsigned char iv[32];

	/* Decrypt the private blob. */
	if (cur_salt->cipher) {
		unsigned char key[40];
		SHA_CTX s;
		if (cur_salt->private_blob_len % cur_salt->cipherblk)
			goto error;

		SHA1_Init(&s);
		SHA1_Update(&s, (void*)"\0\0\0\0", 4);
		SHA1_Update(&s, passphrase, passlen);
		SHA1_Final(key + 0, &s);
		SHA1_Init(&s);
		SHA1_Update(&s, (void*)"\0\0\0\1", 4);
		SHA1_Update(&s, passphrase, passlen);
		SHA1_Final(key + 20, &s);
		memset(iv, 0, 32);
		memset(&akey, 0, sizeof(AES_KEY));
		if(AES_set_decrypt_key(key, 256, &akey) < 0) {
			fprintf(stderr, "AES_set_derypt_key failed!\n");
		}
		AES_cbc_encrypt(cur_salt->private_blob, out , cur_salt->private_blob_len, &akey, iv, AES_DECRYPT);
	}
	/* Verify the MAC. */
	{
		char realmac[41];
		unsigned char binary[20];
		unsigned char *macdata;
		int maclen;
		int free_macdata;
		int i;
		if (cur_salt->old_fmt) {
			/* MAC (or hash) only covers the private blob. */
			macdata = out;
			maclen = cur_salt->private_blob_len;
			free_macdata = 0;
		} else {
			unsigned char *p;
			int namelen = strlen(cur_salt->alg);
			int enclen = strlen(cur_salt->encryption);
			int commlen = strlen(cur_salt->comment);
			maclen = (4 + namelen +
					4 + enclen +
					4 + commlen +
					4 + cur_salt->public_blob_len +
					4 + cur_salt->private_blob_len);
			macdata = (unsigned char*)malloc(maclen);
			p = macdata;
#define DO_STR(s,len) PUT_32BIT(p,(len));memcpy(p+4,(s),(len));p+=4+(len)
			DO_STR(cur_salt->alg, namelen);
			DO_STR(cur_salt->encryption, enclen);
			DO_STR(cur_salt->comment, commlen);
			DO_STR(cur_salt->public_blob, cur_salt->public_blob_len);
			DO_STR(out, cur_salt->private_blob_len);
			free_macdata = 1;
		}
		if (cur_salt->is_mac) {
			SHA_CTX s;
			unsigned char mackey[20];
			unsigned int length = 20;
			// HMAC_CTX ctx;
			char header[] = "putty-private-key-file-mac-key";
			SHA1_Init(&s);
			SHA1_Update(&s, header, sizeof(header)-1);
			if (cur_salt->cipher && passphrase)
				SHA_Update(&s, passphrase, passlen);
			SHA1_Final(mackey, &s);
			hmac_sha1(mackey, 20, macdata, maclen, binary, length);
			/* HMAC_Init(&ctx, mackey, 20, EVP_sha1());
			 * HMAC_Update(&ctx, macdata, maclen);
			 * HMAC_Final(&ctx, binary, &length);
			 * HMAC_CTX_cleanup(&ctx); */
		} else {
			SHA_Simple(macdata, maclen, binary);
		}
		if (free_macdata)
			MEM_FREE(macdata);
		for (i = 0; i < 20; i++)
			sprintf(realmac + 2 * i, "%02x", binary[i]);

		if (strcmp(cur_salt->mac, realmac) == 0)
			return 1;
	}

error:
	return 0;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		cracked[index] = LAME_ssh2_load_userkey(saved_key[index]);
		if(cracked[index])
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

struct fmt_main fmt_putty = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		putty_tests
	},
	{
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		putty_set_key,
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
