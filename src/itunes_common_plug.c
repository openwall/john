/*
 * Common code for the Apple iTunes Backup format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "itunes_common.h"
#include "johnswap.h"
#include "aes.h"

int itunes_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int version, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version
		goto err;
	if (!isdec(p))
		goto err;
	version = atoi(p);
	if (version != 9 && version != 10)  // 9 => iTunes Backup < 10, 10 => iTunes Backup 10.x
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // wpky
		goto err;
	if (hexlenl(p, &extra) != WPKYLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)  // salt
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;

	if (version == 10) {
		if ((p = strtokm(NULL, "*")) == NULL)  // dpic
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)  // dpsl
			goto err;
		if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
			goto err;
	}

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *itunes_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(struct custom_salt), sizeof(uint64_t));

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs->version = atoi(p); // version
	p = strtokm(NULL, "*"); // wpky
	for (i = 0; i < WPKYLEN; i++)
		cs->wpky.chr[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
#if ARCH_LITTLE_ENDIAN
	for (i = 0; i < WPKYLEN / 8; i++)
		cs->wpky.qword[i] = JOHNSWAP64(cs->wpky.qword[i]);
#endif
	p = strtokm(NULL, "*"); // iterations
	cs->iterations = atoi(p);
	p = strtokm(NULL, "*"); // salt
	for (i = 0; i < SALTLEN; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	if (cs->version == 10) {
		p = strtokm(NULL, "*"); // outer iterations
		cs->dpic = atol(p);
		p = strtokm(NULL, "*"); // outer salt
		for (i = 0; i < SALTLEN; i++)
			cs->dpsl[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);

	return (void *)cs;
}

/*
 * Translated from "AESUnwrap" function in aeswrap.py from https://github.com/dinosec/iphone-dataprotection project.
 *
 * The C implementation "aes_key_unwrap" in ramdisk_tools/bsdcrypto/key_wrap.c doesn't look any better.
 */
int itunes_common_decrypt(struct custom_salt *cur_salt, unsigned char *key)
{
	uint64_t *C = cur_salt->wpky.qword;
	int n = 4;  // len(C) - 1
	uint64_t R[5]; // n + 1 = 5
	union {
		uint64_t qword[2];
		unsigned char stream[16];
	} todecrypt;
	int i, j;
	AES_KEY akey;
	uint64_t A = C[0];

	AES_set_decrypt_key(key, 256, &akey);

	for (i = 0; i < n + 1; i++)
		R[i] = C[i];

	for (j = 5; j >= 0; j--) {
		for (i = 4; i >=1; i--) {
#if ARCH_LITTLE_ENDIAN
			todecrypt.qword[0] = JOHNSWAP64(A ^ (n*j+i));
			todecrypt.qword[1] = JOHNSWAP64(R[i]);
			AES_ecb_encrypt(todecrypt.stream, todecrypt.stream, &akey, AES_DECRYPT);
			A = JOHNSWAP64(todecrypt.qword[0]);
			R[i] = JOHNSWAP64(todecrypt.qword[1]);
#else
			todecrypt.qword[0] = A ^ (n*j+i);
			todecrypt.qword[1] = R[i];
			AES_ecb_encrypt(todecrypt.stream, todecrypt.stream, &akey, AES_DECRYPT);
			A = todecrypt.qword[0];
			R[i] = todecrypt.qword[1];
#endif
		}
	}

	if (A == 0xa6a6a6a6a6a6a6a6ULL)
		return 1; // success!

	return 0;
}

unsigned int itunes_common_tunable_version(void *salt)
{
	struct custom_salt *cs = salt;

	return cs->version;
}

unsigned int itunes_common_tunable_iterations(void *salt)
{
	struct custom_salt *cs = salt;

	// this is not a perfect
	if (cs->iterations > cs->dpic)
		return cs->iterations;
	else
		return cs->dpic;
}
