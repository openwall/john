/*
 * Common code for the PGP SDA format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "pgpsda_common.h"
#include "sha.h"

struct fmt_tests pgpsda_tests[] = {
	// Windows XP SP3 + PGP 8.0 generated SDAs
	{"$pgpsda$0*16000*12ad24b8dd12b751*19504b5f4e85c760", "openwall"},
	{"$pgpsda$0*16000*1e9be7b5ff672e90*7393cd5cdda0ca1f", "12345678"},
	// Windows 7 + Symantec Encryption Desktop 10.4.1 MP1
	{"$pgpsda$0*16000*3eb37ca9dfc4f161*fc937f6faaa07355", "åååååååå"},
	{NULL}
};

int pgpsda_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "*")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // iterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) != 8 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "*")) == NULL) // CheckBytes
		goto bail;
	if (hexlenl(p, &extra) != 8 * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

void *pgpsda_common_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;

	memset(&cs, 0, sizeof(cs));
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);
	p = strtokm(NULL, "*");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "*");
	cs.salt_size = 8;
	for (i = 0; i < cs.salt_size; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}

unsigned int pgpsda_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int)cs->iterations;
}
