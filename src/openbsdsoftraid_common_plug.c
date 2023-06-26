/*
 * Common code for the OpenBSD-SoftRAID format.
 *
 * This file takes replicated but common code, shared between the CPU
 * and the GPU formats, and places it into one common location.
 */

#include "misc.h"
#include "common.h"
#include "openbsdsoftraid_common.h"

int openbsdsoftraid_valid(char* ciphertext, struct fmt_main *self, int is_cpu)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int kdf_type;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;

	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (!isdec(p)) /* iterations */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != 2 * 128) /* salt */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != 2 * 32 * 64) /* masked keys */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)
		goto err;
	if (strlen(p) != 2 * BINARY_SIZE) /* HMAC-SHA1 */
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "$")) != NULL) { /* kdf type */
		if (strlen(p) != 1)
			goto err;
		if (!isdec(p))
			goto err;
		kdf_type = atoi(p);
		if (kdf_type != 1 && kdf_type != 3)
			goto err;
		if (!is_cpu && kdf_type != 1)
			goto err;
	}
	if (strtokm(NULL, "$")) /* no more fields */
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *openbsdsoftraid_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "$"); /* iterations */
	cs.num_iterations = atoi(p);
	p = strtokm(NULL, "$");   /* salt */
	for (i = 0; i < OPENBSD_SOFTRAID_SALTLENGTH ; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");   /* masked keys */
	for (i = 0; i < OPENBSD_SOFTRAID_KEYLENGTH * OPENBSD_SOFTRAID_KEYS; i++)
		cs.masked_keys[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "$");   /* binary hash */
	p = strtokm(NULL, "$");   /* kdf type */
	if (p)
		cs.kdf_type = atoi(p);
	else
		cs.kdf_type = 1;

	MEM_FREE(keeptr);

	return (void *)&cs;
}

void *openbsdsoftraid_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;

	if (strlen(p) == 1) { // hack, last field is kdf type
		p -= 2 * BINARY_SIZE + 1;
	}
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

/* Report kdf type as tunable cost */
unsigned int openbsdsoftraid_get_kdf_type(void *salt)
{
	return ((struct custom_salt*)salt)->kdf_type;
}

/* Report iteration count as tunable cost */
unsigned int openbsdsoftraid_get_iteration_count(void *salt)
{
	return ((struct custom_salt*)salt)->num_iterations;
}
