/*
 * Common code for the Telegram Desktop format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "arch.h"
/* We undefine these locally, for scalar PBKDF2 functions used in check_unset_password() */
#undef SIMD_COEF_32
#undef SIMD_COEF_64
#include "pbkdf2_hmac_sha1.h"
#include "pbkdf2_hmac_sha512.h"
#include "aes_ige.h"
#include "telegram_common.h"
#include "jumbo.h"
#include "john.h"

struct fmt_tests telegram_tests[] = {
	// Telegram Desktop 1.3.9 on Ubuntu 18.04 LTS
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*d6fb7ebda06a23a9c42fc57c39e2c3128da4ee1ff394f17c2fc4290229e13d1c9e45c42ef1aee64903e5904c28cffd49498358fee96eb01888f2251715b7a5e71fa130918f46da5a2117e742ad7727700e924411138bb8d4359662da0ebd4f4357d96d1aa62955e44d4acf2e2ac6e0ce057f48fe24209090fd35eeac8a905aca649cafb2aade1ef7a96a7ab44a22bd7961e79a9291b7fea8749dd415f2fcd73d0293cdb533554f396625f669315c2400ebf6f1f30e08063e88b59b2d5832a197b165cdc6b0dc9d5bfa6d5e278a79fa101e10a98c6662cc3d623aa64daada76f340a657c2cbaddfa46e35c60ecb49e8f1f57bc170b8064b70aa2b22bb326915a8121922e06e7839e62075ee045b8c82751defcba0e8fb75c32f8bbbdb8b673258", "openwall123"},
	{"$telegram$1*4000*e693c27ff92fe83a5a247cce198a8d6a0f3a89ffedc6bcddbc39586bb1bcb50b*7c04a5becb2564fe4400c124f5bb5f1896117327d8a21f610bd431171f606fa6e064c088aacc59d8eae4e6dce539abdba5ea552f5855412c26284bc851465d6b31949b276f4890fc212d63d73e2ba132d6098688f2a6408b9d9d69c3db4bcd13dcc3a5f80a7926bb11eb2c99c7f02b5d9fd1ced974d18ed9d667deae4be8df6a4a97ed8fae1da90d5131a7536535a9bfa8094ca7f7465deabef00ab4c715f151d016a879197b328c74dfad5b1f854217c741cf3e0297c63c3fb4d5d672d1e31d797b2c01cb8a254f80a37b6c9a011d864c21c4145091f22839a52b6daf23ed2f350f1deb275f1b0b4146285ada0f0b168ce54234854b19ec6657ad0a92ffb0f3b86547c8b8cc3655a29797c398721e740ed606a71018d16545c78ee240ff3635", "öye"},
#ifndef OPENCL_FORMAT
	// Newer version, starting with 2.1.14 beta or 2.2.0 major release
	{"$telegram$2*100000*0970f6c043d855aa895703b8a1cc086109cf081f72a77b6504f7f4bf3db06420*129294a5eac3196a4c9a88e556f7507b0957f6dd45d704db8abe607ec6d807270c02635289056256a6044a6408e7ef5d33f98c561f16f8aedd2b3ae33ddffddc63c8584dcb232c9f610953f461adb8d29da83f2b01e32db98101febffae4072703bfbfd492e1dd6abeb0926d3df2ed3b47dee4eb6c9f42ab657f89f19d7314c07e2ffc843e448c6d324e9f8d2c3e877a25b0b153736fddb35f5205737620ba2f96aa47f799366150b4de89a0c6e12caa4f03553d164ce9e2e975aadc83538e6ae3df93acb6026f97ac9f6f017a6bbc6607767e591b2c732e3c0ac844584c69dae89ca3272c996eb83b4e66976e3851cfc89be11dc602bb8c0cdf578d9a0a9dbc2296888fa5ee7e58d985a9bf9a1dbc75d2ddfd6ce222c5ee9f3bb40f6e25c2cd", "0404"},
	{"$telegram$2*100000*77461dcb457ce9539f8e4235d33bd12455b4a38446e63b52ecdf2e7b65af4476*f705dda3247df6d690dfc7f44d8c666979737cae9505d961130071bcc18eeadaef0320ac6985e4a116834c0761e55314464aae56dadb8f80ab8886c16f72f8b95adca08b56a60c4303d84210f75cfd78a3e1a197c84a747988ce2e1b247397b61041823bdb33932714ba16ca7279e6c36b75d3f994479a469b50a7b2c7299a4d7aadb775fb030d3bb55ca77b7ce8ac2f5cf5eb7bdbcc10821b8953a4734b448060246e5bb93f130d6d3f2e28b9e04f2a064820be562274c040cd849f1473d45141559fc45da4c54abeaf5ca40d2d57f8f8e33bdb232c7279872f758b3fb452713b5d91c855383f7cec8376649a53b83951cf8edd519a99e91b8a6cb90153088e35d9fed332c7253771740f49f9dc40c7da50352656395bbfeae63e10f754d24a", "hashcat"},
#endif
	{NULL}
};

int telegram_check_password(unsigned char *authkey, struct custom_salt *cs)
{
	AES_KEY aeskey;
	unsigned char data_a[48];
	unsigned char data_b[48];
	unsigned char data_c[48];
	unsigned char data_d[48];
	unsigned char sha1_a[20];
	unsigned char sha1_b[20];
	unsigned char sha1_c[20];
	unsigned char sha1_d[20];
	unsigned char message_key[16];
	unsigned char aes_key[32];
	unsigned char aes_iv[32];
	unsigned char encrypted_data[ENCRYPTED_BLOB_LEN];
	unsigned char decrypted_data[ENCRYPTED_BLOB_LEN];
	int encrypted_data_length = cs->encrypted_blob_length - 16;
	SHA_CTX ctx;

	// setup buffers
	memcpy(message_key, cs->encrypted_blob, 16);
	memcpy(encrypted_data, cs->encrypted_blob + 16, encrypted_data_length);

	memcpy(data_a, message_key, 16);
	memcpy(data_b + 16, message_key, 16);
	memcpy(data_c + 32, message_key, 16);
	memcpy(data_d, message_key, 16);

	memcpy(data_a + 16, authkey + 8, 32);
	memcpy(data_b, authkey + 40, 16);
	memcpy(data_b + 32, authkey + 56, 16);
	memcpy(data_c, authkey + 72, 32);
	memcpy(data_d + 16, authkey + 104, 32);

	// kdf
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_a, 48);
	SHA1_Final(sha1_a, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_b, 48);
	SHA1_Final(sha1_b, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_c, 48);
	SHA1_Final(sha1_c, &ctx);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data_d, 48);
	SHA1_Final(sha1_d, &ctx);

	memcpy(aes_key, sha1_a, 8);
	memcpy(aes_key + 8, sha1_b + 8, 12);
	memcpy(aes_key + 20, sha1_c + 4, 12);

	memcpy(aes_iv, sha1_a + 8, 12);
	memcpy(aes_iv + 12, sha1_b, 8);
	memcpy(aes_iv + 20, sha1_c + 16, 4);
	memcpy(aes_iv + 24, sha1_d, 8);

	// decrypt
	AES_set_decrypt_key(aes_key, 256, &aeskey);
	JtR_AES_ige_encrypt(encrypted_data, decrypted_data, encrypted_data_length, &aeskey, aes_iv, AES_DECRYPT);

	// verify
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, decrypted_data, encrypted_data_length);
	SHA1_Final(sha1_a, &ctx);

	return !memcmp(sha1_a, message_key, 16);
}

void *telegram_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.salt_length = strlen(p) / 2;
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "*");
	cs.encrypted_blob_length = strlen(p) / 2;
	for (i = 0; i < cs.encrypted_blob_length; i++)
		cs.encrypted_blob[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);

	return &cs;
}

static int check_unset_password(char *ciphertext, struct fmt_main *self)
{
	struct custom_salt *salt = telegram_get_salt(ciphertext);
	unsigned char pkey[256];

	if (salt->version == 1)
		pbkdf2_sha1((unsigned char*)"", 0, salt->salt, salt->salt_length, 4, pkey, 136, 0);
	else { /* if (salt->version == 2) */
		SHA512_CTX ctx;
		unsigned char pbkdf2_key[64];

		/* This is the $s.$p.$s, but with an empty password */
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, salt->salt, salt->salt_length);
		SHA512_Update(&ctx, salt->salt, salt->salt_length);
		SHA512_Final(pbkdf2_key, &ctx);

		pbkdf2_sha512(pbkdf2_key, 64, salt->salt, salt->salt_length, 1, pkey, 136, 0);
	}
	if (telegram_check_password(pkey, salt)) {
		if (john_main_process)
			fprintf(stderr, "%s: Note: No password set for '%.35s(...)', ignoring\n", self->params.label, ciphertext);
		return 0;
	}

	return 1;
}

int telegram_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int version, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL)  // version / type
		goto err;
	if (!isdec(p))
		goto err;
	version = atoi(p);
#ifdef OPENCL_FORMAT
	if (version != 1)
#else
	if (version != 1 && version != 2)
#endif
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // rounds
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // salt
		goto err;
	if (hexlenl(p, &extra) > SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // encrypted_blob
		goto err;
	if (hexlenl(p, &extra) > ENCRYPTED_BLOB_LEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return check_unset_password(ciphertext, self);

err:
	MEM_FREE(keeptr);
	return 0;
}

unsigned int telegram_iteration_count(void *salt)
{
	struct custom_salt *cs = (struct custom_salt*)salt;

	return cs->iterations;
}
