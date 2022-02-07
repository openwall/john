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
	char *ctcopy = xstrdup(ciphertext);
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
	size_t len;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL)  // version / type
		goto err;
	if (!isdec(p))
		goto err;
	version = atoi(p);
	if (version != 1 && version != 2)
		goto err;
	if (version == 2 && strstr(self->params.label, "-opencl")) {
		static int warned;

		if (john_main_process && !warned++)
			fprintf(stderr, "Warning: Telegram-opencl currently doesn't support v2 hashes.\n");
		goto err;
	}
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
	len = hexlenl(p, &extra);
	if (len < 16 * 2 || len > ENCRYPTED_BLOB_LEN * 2 || extra)
		goto err;
	if (strtokm(NULL, "*"))  // no more fields
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
