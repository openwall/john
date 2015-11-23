/*
 * Common code for the Apple iWork format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "iwork_common.h"
#include "hmac_sha.h"
#include "memdbg.h"

int iwork_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value;
	int file_version;
	int salt_length; // this is "someSalt" for iWork '09 files

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // internal (to JtR) format version
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value !=2)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // file version
		goto err;
	if (!isdec(p))
		goto err;
	file_version = atoi(p);
	if (file_version != 1 && file_version != 2) // iWork '09, iWork 2013
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // format
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (file_version == 1)
		salt_length = 8;
	else
		salt_length = SALTLEN;
	if (hexlenl(p) != salt_length * 2)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iv
		goto err;
	if (hexlenl(p) != IVLEN * 2)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // blob
		goto err;
	if (hexlenl(p) != BLOBLEN * 2)
		goto err;
	if ((p = strtokm(NULL, "$")) != NULL)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *iwork_common_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	int file_version;
	static struct format_context *fctx;

	fctx = mem_calloc_tiny(sizeof(struct format_context), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // internal version
	p = strtokm(NULL, "$"); // version
	file_version = atoi(p);
	if (file_version == 1)
		fctx->salt_length = 8;
	else
		fctx->salt_length = SALTLEN;
	p = strtokm(NULL, "$"); // fmt
	p = strtokm(NULL, "$"); // iterations
	fctx->iterations = atoi(p);
	p = strtokm(NULL, "$"); // salt
	for (i = 0; i < SALTLEN; i++)
		fctx->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // iv
	for (i = 0; i < IVLEN; i++)
		fctx->iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // blob
	for (i = 0; i < BLOBLEN; i++)
		fctx->blob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);

	return (void *)fctx;
}

int iwork_common_decrypt(struct format_context *fctx, unsigned char *key, unsigned char *iv, unsigned char *data)
{
	unsigned char out[BLOBLEN] = {0};
	unsigned char ivec[IVLEN];
	uint8_t hash[32];
	SHA256_CTX ctx;
	AES_KEY aes_decrypt_key;

	AES_set_decrypt_key(key, 128, &aes_decrypt_key);
	memcpy(ivec, iv, 16);
	AES_cbc_encrypt(fctx->blob, out, BLOBLEN, &aes_decrypt_key, ivec, AES_DECRYPT);

	// The last 32 bytes should be equal to the SHA256 of the first 32 bytes (IWPasswordVerifier.m)
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, out, 32);
	SHA256_Final(hash, &ctx);

	return memcmp(hash, &out[32], 32) == 0;
}

unsigned int iwork_common_iteration_count(void *salt)
{
	struct format_context *my_fctx;

	my_fctx = salt;
	return (unsigned int) my_fctx->iterations;
}
