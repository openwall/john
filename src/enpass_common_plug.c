/*
 * Common code for the Enpass Password Manager format.
 */

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "enpass_common.h"

int enpass_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int extra;
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* version */
		goto err;
	if (atoi(p) != 0 && atoi(p) != 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iterations */
		goto err;
	if (atoi(p) < 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* salt + data */
		goto err;
	if (hexlenl(p, &extra) != 2048 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *enpass_get_salt(char *ciphertext)
{
	int i;
	char *p = ciphertext;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));

	p = ciphertext + FORMAT_TAG_LEN;
	cs.version = atoi(p) == 0 ? 5 : 6;
	p = strchr(p, '$') + 1;
	cs.iterations = atoi(p);
	cs.salt_length = 16; // fixed

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	for (; i < 1024; i++)
		cs.data[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];

	return (void *)&cs;
}
unsigned int enpass_version(void *salt)
{
	return ((struct custom_salt*)salt)->version;
}
