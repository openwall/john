/*
 * Common code for the FileVault 2 format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "fvde_common.h"
#include "hmac_sha.h"
#include "johnswap.h"

struct fmt_tests fvde_tests[] = {
	// https://github.com/kholia/fvde2john/blob/master/fvde-1.raw.tar.xz
	{"$fvde$1$16$e7eebaabacaffe04dd33d22fd09e30e5$41000$e9acbb4bc6dafb74aadb72c576fecf69c2ad45ccd4776d76", "openwall"},
	// external disk encrypted by macOS 10.12.2
	{"$fvde$1$16$94c438acf87d68c2882d53aafaa4647d$70400$2deb811f803a68e5e1c4d63452f04e1cac4e5d259f2e2999", "password123"},
	// external disk encrypted by macOS 10.13.5 (apfs), use https://github.com/kholia/apfs2john to extract such hashes
	{"$fvde$2$16$0d7426917b673738a1e39c987ec0f477$181461$450319e1181941d5fb77d2a200c03ace7ebec71b76c56cb9faa9216403aa6be9df2118ddcac19c62", "openwall"},
	{NULL}
};

int fvde_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;
	int salt_length;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version, for future purposes
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1 && value != 2)
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
	value = hexlenl(p, &extra);
	if (((value != 24 * 2) && (value != BLOBLEN * 2)) || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *fvde_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static fvde_custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(fvde_custom_salt), sizeof(uint64_t));

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // version
	cs->type = atoi(p);
	p = strtokm(NULL, "$"); // salt length
	cs->salt_length = atoi(p);
	p = strtokm(NULL, "$"); // salt
	for (i = 0; i < cs->salt_length; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$"); // iterations
	cs->iterations = atoi(p);
	p = strtokm(NULL, "$"); // blob
	cs->bloblen = strlen(p) / 2;
	for (i = 0; i < cs->bloblen; i++)
		cs->blob.chr[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
#if ARCH_LITTLE_ENDIAN
	for (i = 0; i < cs->bloblen / 8; i++)
		 cs->blob.qword[i] = JOHNSWAP64(cs->blob.qword[i]);
#endif
	MEM_FREE(keeptr);

	return (void *)cs;
}

unsigned int fvde_common_iteration_count(void *salt)
{
	fvde_custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
