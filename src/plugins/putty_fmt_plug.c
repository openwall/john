/*
 * PuTTY private key cracker patch for JtR. Hacked together during Monsoon of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is based on p-ppk-crack v0.5 (PuTTY private key cracker) made
 * by michu@neophob.com. In turn, p-ppk-crack is based on PuTTY SVN version.
 * See [1] for the exact licensing terms.
 *
 * [1] http://www.chiark.greenend.org.uk/~sgtatham/putty/licence.html
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_putty;
#elif FMT_REGISTERS_H
john_register_one(&fmt_putty);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "misc.h"
#include "aes.h"
#include "sha.h"
#include "hmac_sha.h"
#include "loader.h"

#define FORMAT_LABEL        "PuTTY"
#define FORMAT_NAME         "Private Key (RSA/DSA/ECDSA/ED25519)"
#define FORMAT_TAG          "$putty$"
#define FORMAT_TAG_LEN      (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME      "SHA1/AES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0x107
#define PLAINTEXT_LENGTH    32
#define BINARY_SIZE         0
#define BINARY_ALIGN        1
#define SALT_SIZE           sizeof(struct custom_salt)
#define SALT_ALIGN          4
#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  64

#ifndef OMP_SCALE
#define OMP_SCALE           128
#endif

#define PUT_32BIT_MSB_FIRST(cp, value) (	  \
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
	char alg[32];
	int cipher, cipherblk;
	int public_blob_len, private_blob_len;
	char encryption[32];
	char mac[20];
	char comment[512];
	unsigned char public_blob[4096];
	unsigned char private_blob[4096];
} *cur_salt;

static struct fmt_tests putty_tests[] = {
	{"$putty$1*16*1*0*10c434c33cf160352b7a5b3a1ecd8434f1066cac*432*000000077373682d647373000000806bb7ed4d03163f5be550dba68e0f1af7dae4b49f736ab452552a1163210c1366fd1f65a31bb526b1d3028a31d30b3315c19dc02417db99336f00b1f9565431d02fc59cd756ab6fe506b959df3799e4a70fcbe54ad9ef34d338014add8ac1f57f2a6dce8403c93709cb23d3c379f5de4f9fc45a73b3f9a43e6c1cc220bd38274b0000001500b4bf70cda203027a13135d43e459872eed384a3d0000008049a7d8e8d1db1630f9a9f6b1bf275d01e4287a4c2f038707d8c07ab664dbd264f6b4676de93c1f003bb57146a82314ab6c426628498209fa33c68a881abfd90dc1e978d430c9ace78d6c9895938494e91e3ca50132c9bde8fae4381e6fe59d03a9feee39b10cb2fea4e4d5f5ef10e523d34925f105eff665db2ac35e6cf0a1ac000000800def6e4f7ed4af0f1f8ed9524595d3fecd0a191ea9a6402d4235ee59ff2000011e36b5936280a3b5dc0b8d8ea7747e04ad92e46be8cb374d931c1e78bbdafea4ac16aba2e4b3cbd0779d28a609e848fb54332a169f24fac5e4c736c3dae4f95afe0aacaffb2d4829956fbd17d514614a45f8eefdd0d7d4982d101d72002f05fd*32*b38180c482949f3b4f44a20fd599c2cb411c671b4b120663bef9a61b360e442a*ssh-dss*aes256-cbc*dsa-key-20120721", "password"},
	{"$putty$1*16*1*0*0dbfd7b4ec870df2fb8becc9efa6feeec683cd98*149*000000077373682d727361000000012500000081008ffc01db52ff6543a67b747e9882d04c32dc769b0b1fa575e1e838133d0bc381291af654b112a6ead07b157e5556d2052c7d516b605415687769f1095e2107067e08cc569e6382b31a42d93bbb4c189c01469872b65e50af3f81ed651cb4144c556cadefda8706f00c65699a074fc4fa5843a8370852d04b8f5575f0f2186611*352*9df7f3992f46922e9e03ee381a9ba06082fcf07f572f5a742400fdbdb8fd850161b0dd877ce1fb5433311c097463a8b0c0d7e98f58d361ca1579a01d30878c8b934653ee1278942ee1fbba092e495d2c8b2f5903b7cb3fd1b5c0445d993e3139fa3741dd51e968fb8cc9cc5c257d25cb94d404e448ec334fc1be713c3156a8c9110280623687a7f3c5a8dede7efa98d4bfd12ae8cef634c0c51dcdccf2a9f65e14bd3f5cb34270ad1ea02732d653073fc2e772e3dfea14fa29a50052831bafedd10bd73a13c52db956e2b674115d9620cc1136432edc4e2968681d177278999cda7cc6aeb9e2427a11f2aee67990c02a400144fab0cf4546d19726247a076423384bd98c3d6fb810ab5ee7ff248b8a87a6652dff7deb38349b9929ba29375dcdd90c7e01ad6900b48cf48300dd157cc80ae94a1d6e7545ec7fcaf96e0172acf08ee7e21e494ca601f5890ad9e8ca5ff89141aa50ae188842da52ae000d38d1fa*ssh-rsa*aes256-cbc*rsa-key-20120721", "openwall"},
	/* PuTTYgen 0.70 from July, 2017 */
	{"$putty$1*16*1*0*69396df4513221459e8302f2b84b56d1f078cce1*51*0000000b7373682d6564323535313900000020abed4c34945b8e98fad03669eba5911b5890e7070d5212547128c2b586c9cba5*48*878992fc0f3bd20a88d182bb9f765ceb259e1076da2c7d4a0987b95bc692c690886f2020b5959399550cb9224cc71f1a*ssh-ed25519*aes256-cbc*ed25519-key-20170722", "openwall"},
	{"$putty$1*16*1*0*d931af6335088577da918d60a77f3c097d76620a*104*0000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041046bb900eb809a5be6ec1bda5aac286ac9a2e0c7e0bfab317623ccf9b8b47baaedc0a2498287df6cb3a07165461b40ac1dba2f492be96ec841bfcbf93df9d31a43*48*ba7ba53ca50e05e15ba4ea19f2c6891298af84bf7280ea4bdcb7fa0611a9816a5966f972cd4a1eee37a42ac69489601c*ecdsa-sha2-nistp256*aes256-cbc*ecdsa-key-20170722", "openwall"},
	{NULL}
};

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	any_cracked = 0;
	cracked_size = sizeof(*cracked) * self->params.max_keys_per_crypt;
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res, extra;
	int is_old_fmt;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL) /* cipher */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res != 1) /* check cipher type */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* cipher block length*/
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res != 16) /* check cipher block length */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* is_mac */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* old_fmt */
		goto err;
	if (!isdec(p))
		goto err;
	is_old_fmt = atoi(p);
	if (is_old_fmt != 0 && is_old_fmt!= 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* mac */
		goto err;
	res = strlen(p);
	if (res > 128)
		goto err;
	if (hexlenl(p, &extra) != res || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* public_blob_len */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 4096)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* public_blob */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* private_blob_len */
		goto err;
	if (!isdec(p))
		goto err;
	res = atoi(p);
	if (res > 4096)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* private_blob */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if (!is_old_fmt) {
		if ((p = strtokm(NULL, "*")) == NULL)	/* alg */
			goto err;
		if (strlen(p) > 31)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* encryption */
			goto err;
		if (strlen(p) > 32)
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)	/* comment */
			goto ok;  // since comment is optional
		if (strlen(p) > 512)
			goto err;
	}

ok:
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
	/* ensure alignment */
	static union {
		struct custom_salt _cs;
		uint32_t dummy;
	} un;
	struct custom_salt *cs = &(un._cs);

	memset(cs, 0, sizeof(un));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$putty$" marker */
	p = strtokm(ctcopy, "*");
	cs->cipher = atoi(p);
	p = strtokm(NULL, "*");
	cs->cipherblk = atoi(p);
	p = strtokm(NULL, "*");
	cs->is_mac = atoi(p);
	p = strtokm(NULL, "*");
	cs->old_fmt = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 20; i++)
		cs->mac[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs->public_blob_len = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs->public_blob_len; i++)
		cs->public_blob[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs->private_blob_len = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs->private_blob_len; i++)
		cs->private_blob[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	if (!cs->old_fmt) {
		p = strtokm(NULL, "*");
		strcpy(cs->alg, p);
		p = strtokm(NULL, "*");
		strcpy(cs->encryption, p);
		p = strtokm(NULL, "*");
		if (p)
			strcpy(cs->comment, p);
	}
	MEM_FREE(keeptr);
	return (void *)cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void putty_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
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
	unsigned char out[sizeof(cur_salt->private_blob)];
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
		AES_set_decrypt_key(key, 256, &akey);
		AES_cbc_encrypt(cur_salt->private_blob, out , cur_salt->private_blob_len, &akey, iv, AES_DECRYPT);
	}
	/* Verify the MAC. */
	{
		unsigned char binary[20];
		unsigned char *macdata;
		unsigned char macdata_ar[4*5+sizeof(cur_salt->alg)+sizeof(cur_salt->encryption)+sizeof(cur_salt->comment)+sizeof(cur_salt->public_blob)+sizeof(cur_salt->private_blob)+1];
		int maclen;

		if (cur_salt->old_fmt) {
			/* MAC (or hash) only covers the private blob. */
			macdata = out;
			maclen = cur_salt->private_blob_len;
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
			p = macdata_ar;
#define DO_STR(s,len) PUT_32BIT(p,(len));memcpy(p+4,(s),(len));p+=4+(len)
			DO_STR(cur_salt->alg, namelen);
			DO_STR(cur_salt->encryption, enclen);
			DO_STR(cur_salt->comment, commlen);
			DO_STR(cur_salt->public_blob, cur_salt->public_blob_len);
			DO_STR(out, cur_salt->private_blob_len);
			macdata = macdata_ar;
		}
		if (cur_salt->is_mac) {
			SHA_CTX s;
			unsigned char mackey[20];
			unsigned int length = 20;
			char header[] = "putty-private-key-file-mac-key";

			SHA1_Init(&s);
			SHA1_Update(&s, header, sizeof(header)-1);
			if (cur_salt->cipher && passphrase)
				SHA1_Update(&s, passphrase, passlen);
			SHA1_Final(mackey, &s);
			hmac_sha1(mackey, 20, macdata, maclen, binary, length);
		} else {
			SHA_Simple(macdata, maclen, binary);
		}
		if (memcmp(cur_salt->mac, binary, 20) == 0)
			return 1;
	}

error:
	return 0;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;

	if (any_cracked) {
		memset(cracked, 0, cracked_size);
		any_cracked = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		cracked[index] = LAME_ssh2_load_userkey(saved_key[index]);
		if (cracked[index])
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
	}

	return count;
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
		putty_tests
	},
	{
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

#endif /* plugin stanza */
