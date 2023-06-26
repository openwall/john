/*
 * Common code for the Ansible Vault format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "ansible_common.h"

struct fmt_tests ansible_tests[] = {
	{"$ansible$0*0*f623a48ba49f7abf7c1920bc1e2ab2607cda2b5786da2560b8178a6095e5dfd2*ab55de42e4f131f109f1a086f2e8e22f*6767c60857ce1d7aa20226d76ec1abf77837c623bb7e879147ab888ef15a0dbb", "openwall"},
	{"$ansible$0*0*45252709c61203511abbfdab0a8b498cb3e6259be5211e5b33ccc2fe12211d3f*0c52b98fc5aed891f99e3bcd3c6f250a*8e2d7558cd75b293ad8f3e27b774704279c019d89ba4743b591a3b14883c0851", "åbc"},
	{NULL}
};

int ansible_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version, for future purposes
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // cipher (fixed for now)
		goto err;
	if (!isdec(p))
		goto err;
	if (atoi(p) != 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // ciphertext
		goto err;
	if (hexlenl(p, &extra) >= BLOBLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)   // checksum
		goto err;
	if (hexlenl(p, &extra) != 32 * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *ansible_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(struct custom_salt), sizeof(uint64_t));

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	p = strtokm(NULL, "*");
	cs->iterations = 10000;  // fixed
	cs->salt_length = SALTLEN;
	p = strtokm(NULL, "*");
	for (i = 0; i < cs->salt_length; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs->bloblen = strlen(p) / 2;
	for (i = 0; i < cs->bloblen; i++)
		cs->blob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 32; i++)
		cs->checksum[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);

	return (void *)cs;
}

void *ansible_common_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	memset(buf.c, 0, BINARY_SIZE);
	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE_CMP; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

unsigned int ansible_common_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
