/*
 * Common code for the NetIQ SSPR format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "sspr_common.h"
#include "memdbg.h"

int sspr_valid(char *ciphertext, struct fmt_main *self, int is_cpu_format)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL)  // type
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0 && value != 1 && value != 2 && value != 3 && value != 4)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // iterations
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // salt
		goto err;
	if (strlen(p) > MAX_SALT_LEN)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL)  // binary
		goto err;
	value = hexlenl(p, &extra);
	if (value < BINARY_SIZE_MIN * 2 || value > BINARY_SIZE * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *sspr_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;

	memset(&cs, 0, sizeof(struct custom_salt));
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.fmt = atoi(p);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = strlen(p);
	strncpy(cs.salt, p, MAX_SALT_LEN);

	MEM_FREE(keeptr);

	return &cs;
}

void *sspr_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	memset(buf.c, 0, BINARY_SIZE);
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE_MIN; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

unsigned int sspr_get_kdf_type(void *salt)
{
	return ((struct custom_salt *)salt)->fmt;
}
