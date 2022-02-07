/*
 * Common code for Apple Notes format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "notes_common.h"
#include "johnswap.h"

struct fmt_tests notes_tests[] = {
	// macOS 10.13.2 with cloud syncing turned off
	{"$ASN$*4*20000*caff9d98b629cad13d54f5f3cbae2b85*79270514692c7a9d971a1ab6f6d22ba42c0514c29408c998", "openwall"},
	{"$ASN$*4*20000*f5cf417cdec96291463fb0e19868307d*3ed7c0a3df2ecf2baaa0d4593acce83a04bea708446e0556", "åbc"},
	// from hashcat project
	{"$ASN$*1*20000*35317234050571840136152316737833*fdcdf88f2b65f95d5b9225db2c85496e7ebb12e655314460", "hashcat"},
	{NULL}
};

int notes_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // iden (unused)
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // wrapped kek, "blob"
		goto err;
	if (hexlenl(p, &extra) != BLOBLEN * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *notes_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(struct custom_salt), sizeof(uint64_t));

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs->type = 1;
	p = strtokm(NULL, "*");
	cs->iterations = atoi(p);
	cs->salt_length = SALTLEN;
	p = strtokm(NULL, "*");
	for (i = 0; i < cs->salt_length; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < BLOBLEN; i++)
		cs->blob.chr[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
#if ARCH_LITTLE_ENDIAN
	for (i = 0; i < BLOBLEN / 8; i++)
		 cs->blob.qword[i] = JOHNSWAP64(cs->blob.qword[i]);
#endif
	MEM_FREE(keeptr);

	return (void *)cs;
}

unsigned int notes_common_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
