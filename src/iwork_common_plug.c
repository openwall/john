/*
 * Common code for the Apple iWork format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "iwork_common.h"
#include "hmac_sha.h"

struct fmt_tests iwork_tests[] = {
	{"$iwork$1$2$1$100000$d77ce46a68697e08b76ac91de9117541$e7b72b2848dc27efed883963b00b1ac7$e794144cd2f04bd50e23957b30affb2898554a99a3accb7506c17132654e09c04bbeff45dc4f8a8a1db5fd1592f699eeff2f9a8c31b503e9631a25a344b517f7" ,"12345678"},
	// iWork for iCloud (February 2017)
	{"$iwork$1$2$1$100000$9d406f6bbb6d3798273a1352c33ed387$7dfef75b06f8cb0092802ad833d6e88c$fc4dd694e0b5fbb123d1a6f1abec30e51176e6f0d574e4988e9c82d354baa3540e2f2268d096d9e46c1080eda32ca8eb8abfeeaa01466d86706b03eb8bd5f0e5", "Password"},
	{FORMAT_TAG "1$2$1$100000$c773f06bcd580e4afa35618a7d0bee39$8b241504af92416f226d0eea4bf26443$18358e736a0401061f2dca103fceb29e88606d3ec80d09841360cbb8b9dc1d2908c270d3ff4c05cf7a46591e02ff3c9d75f4582f631721a3257dc087f98f523e", "password"},
	// iWork '09 Keynote file
	{"$iwork$2$1$1$4000$736f6d6553616c74$a9d975f8b3e1bf0c388944b457127df4$09eb5d093584376001d4c94e9d0a41eb8a2993132849c5aed8e56e7bd0e8ed50ba38aced793e3480675990c828c01d25fe245cc6aa603c6cb1a0425988f1d3dc", "openwall"},
	{NULL}
};

int iwork_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;
	int file_version;
	int salt_length; // this is "someSalt" for iWork '09 files

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
	if (hexlenl(p, &extra) != salt_length * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)   // iv
		goto err;
	if (hexlenl(p, &extra) != IVLEN * 2 || extra)
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

void *iwork_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
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
	for (i = 0; i < fctx->salt_length; i++)
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

unsigned int iwork_common_iteration_count(void *salt)
{
	struct format_context *my_fctx;

	my_fctx = salt;
	return (unsigned int) my_fctx->iterations;
}
