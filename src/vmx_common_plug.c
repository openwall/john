/*
 * Common code for the VMware VMX format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "vmx_common.h"

struct fmt_tests vmx_tests[] = {
	{"$vmx$1$0$0$10000$514fb565d74db333352661023874f07d$81dc8986e299d55dee724198a572619b87de0b96501dd2285fbe928c831446fb92c056e02e6ca0119213e9cf094222c0e4d0df6f014615c915412cb0c892d4528070ead0d2443d0c457a7db445fd17b060899033a5c69d43315abd3d262ad3570379c12c97fc2490d7a42b04f99a24386f27aa56", "openwall"},
	{"$vmx$1$0$0$10000$55dd70aeff5eb4d52c6fe0d7d970a70d$482f450a75486f618252fda6cb6d0263b2aa05823e318288f5508de2223515fb5390a498632cb144565f40aa6e1ec7d2ca21ef799c16f03d94fd5ee8e61ff5910f98e9081cc235a4f8a42a1fc599c573e06cac5c941ab051e36e3c2328faa26df9f1c9f7d0421d87bc3c6c972e4fdfe4a42146a7", "åbc"},
	{NULL}
};

int vmx_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // internal (to JtR) format version
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // hash algorithm
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // cipher algorithm
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // salt
		goto err;
	if (hexlenl(p, &extra) != SALTLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // blob
		goto err;
	if (hexlenl(p, &extra) != BLOBLEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) != NULL)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *vmx_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt *cs;

	cs = mem_calloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);

	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cs->iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs->salt_length = SALTLEN;
	for (i = 0; i < cs->salt_length; i++)
		cs->salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");
	for (i = 0; i < BLOBLEN; i++)
		cs->blob[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	MEM_FREE(keeptr);

	return (void *)cs;
}

unsigned int vmx_common_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int)cs->iterations;
}
