/*
 * Common code for the LibreOffice format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "libreoffice_common.h"
#include "memdbg.h"

int libreoffice_valid(char *ciphertext, struct fmt_main *self, int is_cpu)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int res, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* cipher type */
		goto err;
	if (strlen(p) != 1)
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum type */
		goto err;
	if (strlen(p) != 1)
		goto err;
	res = atoi(p);
	if (res != 0 && res != 1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* key size */
		goto err;
	res = atoi(p);
	if (res != 16 && res != 32)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* checksum field (skipped) */
		goto err;
	res = hexlenl(p, &extra);
	if (extra)
		goto err;
	if (res != 40 && res != 64) // 2 hash types (SHA-1 and SHA-256)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv length */
		goto err;
	res = atoi(p);
	if (res > 16 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* iv */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt length */
		goto err;
	if (strlen(p) >= 10)
		goto err;
	res = atoi(p);
	if (res > 32 || res < 0)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* something */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* content */
		goto err;
	res = strlen(p);
	if (res > 2048 || res & 1)
		goto err;
	if (!ishexlc(p))
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *libreoffice_get_salt(char *ciphertext)
{
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$odf$*" */
	p = strtokm(ctcopy, "*");
	cs.cipher_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.checksum_type = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.key_size = atoi(p);
	strtokm(NULL, "*");
	/* skip checksum field */
	p = strtokm(NULL, "*");
	cs.iv_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.iv_length; i++)
		cs.iv[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.salt_length = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	strtokm(NULL, "*");
	p = strtokm(NULL, "*");
	for (i = 0; p[i * 2] && i < 1024; i++)
		cs.content[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	cs.content_length = i;
	MEM_FREE(keeptr);

	return (void *)&cs;
}

void *libreoffice_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[32+1];  // max(SHA-1, SHA-256)
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	char *ctcopy = strdup(ciphertext + FORMAT_TAG_LEN);

	memset(&buf, 0, sizeof(buf));
	strtokm(ctcopy, "*");
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	strtokm(NULL, "*");
	p = strtokm(NULL, "*");

	for (i = 0; i < 20; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	MEM_FREE(ctcopy);

	return out;
}

/*
 * The format tests all have iteration count 1024.
 * Just in case the iteration count is tunable, let's report it.
 */
unsigned int libreoffice_iteration_count(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int) my_salt->iterations;
}


