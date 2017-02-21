/*
 * Common code for the FileVault 2 format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "fvde_common.h"
#include "hmac_sha.h"
#include "memdbg.h"
#include "johnswap.h"
#include "aes.h"

struct fmt_tests fvde_tests[] = {
	// https://github.com/kholia/fvde2john/blob/master/fvde-1.raw.tar.xz
	{"$fvde$1$16$e7eebaabacaffe04dd33d22fd09e30e5$41000$e9acbb4bc6dafb74aadb72c576fecf69c2ad45ccd4776d76", "openwall"},
	// external disk encrypted by macOS 10.12.2
	{"$fvde$1$16$94c438acf87d68c2882d53aafaa4647d$70400$2deb811f803a68e5e1c4d63452f04e1cac4e5d259f2e2999", "password123"},
	{NULL}
};

/*
 * Unwrap data using AES Key Wrap (RFC3394)
 *
 * Translated from "AESUnwrap" function in aeswrap.py from https://github.com/dinosec/iphone-dataprotection project.
 *
 * The C implementation "aes_key_unwrap" in ramdisk_tools/bsdcrypto/key_wrap.c doesn't look any better.
 *
 * "libfvde_encryption_aes_key_unwrap" isn't great to look at either.
 */
int fvde_common_decrypt(fvde_custom_salt *cur_salt, unsigned char *key)
{
	uint64_t *C = cur_salt->blob.qword; // len(C) == 3
	int n = 2;  // len(C) - 1
	uint64_t R[3]; // n + 1 = 3
	union {
		uint64_t qword[2];
		unsigned char stream[16];
	} todecrypt;
	int i, j;
	AES_KEY akey;
	uint64_t A = C[0];

	AES_set_decrypt_key(key, 128, &akey);

	for (i = 0; i < n + 1; i++)
		R[i] = C[i];

	for (j = 5; j >= 0; j--) { // 5 is fixed!
		for (i = 2; i >=1; i--) { // i = n
			todecrypt.qword[0] = JOHNSWAP64(A ^ (n*j+i));
			todecrypt.qword[1] = JOHNSWAP64(R[i]);
			AES_ecb_encrypt(todecrypt.stream, todecrypt.stream, &akey, AES_DECRYPT);
			A = JOHNSWAP64(todecrypt.qword[0]);
			R[i] = JOHNSWAP64(todecrypt.qword[1]);
		}
	}

	if (A == 0xa6a6a6a6a6a6a6a6ULL)
		return 1; // success!

	return 0;
}

int fvde_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;
	int salt_length;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version, for future purposes
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt length
		goto err;
	if (!isdec(p))
		goto err;
	salt_length = atoi(p);
	if (salt_length != SALTLEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != salt_length * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // wrapped kek, "blob"
		goto err;
	if (hexlenl(p, &extra) != BLOBLEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *fvde_common_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static fvde_custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(fvde_custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // version
	p = strtokm(NULL, "$"); // salt length
	cs->salt_length = atoi(p);
	p = strtokm(NULL, "$"); // salt
	for (i = 0; i < cs->salt_length; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // iterations
	cs->iterations = atoi(p);
	p = strtokm(NULL, "$"); // blob
	for (i = 0; i < BLOBLEN; i++)
		cs->blob.chr[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	for (i = 0; i < BLOBLEN / 8; i++)
		 cs->blob.qword[i] = JOHNSWAP64(cs->blob.qword[i]);

	MEM_FREE(keeptr);

	return (void *)cs;
}

unsigned int fvde_common_iteration_count(void *salt)
{
	fvde_custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
