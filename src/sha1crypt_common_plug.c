/*
 * sha1crypt cracker patch for JtR, common code. 2014 by JimF
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64_convert.h"
#include "johnswap.h"
#include "sha1crypt_common.h"


struct fmt_tests sha1crypt_common_tests[] = {
	/* retroactively added hashcat's test vector for benchmark compatibility */
	{"$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q", "hashcat"},
	{"$sha1$64000$wnUR8T1U$vt1TFQ50tBMFgkflAFAOer2CwdYZ", "password"},
	{"$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq", "password"},
	{"$sha1$64000$wnUR8T1U$wmwnhQ4lpo/5isi5iewkrHN7DjrT", "123456"},
	{"$sha1$64000$wnUR8T1U$azjCegpOIk0FjE61qzGWhdkpuMRL", "complexlongpassword@123456"},
	{NULL}
};

int sha1crypt_common_valid(char * ciphertext, struct fmt_main * self) {
	char *p, *keeptr, tst[24];
	unsigned rounds;

	if (strncmp(ciphertext, SHA1_MAGIC, SHA1_MAGIC_LEN))
		return 0;

	// validate rounds
	keeptr = xstrdup(ciphertext);
	p = &keeptr[SHA1_MAGIC_LEN];
	if ((p = strtokm(p, "$")) == NULL)	/* rounds */
		goto err;
	rounds = strtoul(p, NULL, 10);
	sprintf(tst, "%u", rounds);
	if (strcmp(tst, p))
		goto err;

	// validate salt
	if ((p = strtokm(NULL, "$")) == NULL)	/* salt */
		goto err;
	if (strlen(p) > SALT_LENGTH || strlen(p) != base64_valid_length(p, e_b64_crypt, 0, 0))
		goto err;

	// validate checksum
	if ((p = strtokm(NULL, "$")) == NULL)	/* checksum */
		goto err;
	if (strlen(p) > CHECKSUM_LENGTH || strlen(p) != base64_valid_length(p, e_b64_crypt, 0, 0))
		goto err;

	if (strtokm(NULL, "$"))
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:;
	MEM_FREE(keeptr);
	return 0;
}

#define TO_BINARY(b1, b2, b3) \
	value = (uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;

void * sha1crypt_common_get_binary(char * ciphertext) {
	static union {
                unsigned char c[BINARY_SIZE + 16];
                ARCH_WORD dummy;
				uint32_t swap[1];
        } buf;
        unsigned char *out = buf.c;
	uint32_t value;

	char *pos = strrchr(ciphertext, '$') + 1;
	int i = 0;

	do {
		TO_BINARY(i, i + 1, i + 2);
		i = i + 3;
	} while (i <= 18);
	return (void *)out;
}
