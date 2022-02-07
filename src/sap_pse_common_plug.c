#include "sap_pse_common.h"

struct fmt_tests sappse_tests[] =
{
	{"$pse$1$2048$8$0000000000000000$0$$8$826a5c4189e18b67", "1234"},
	{"$pse$1$2048$8$0000000000000000$0$$16$4e25e64000fa09dc32b2310a215d246e", "12345678"},
	{"$pse$1$2048$8$0000000000000000$0$$16$70172e6c0eb85edc6344852fb5fd24f3", "1234567890"},
	{"$pse$1$10000$8$0000000000000000$0$$16$4b23ac258610078d0ca66620010850b8", "password"},
	{"$pse$1$10000$8$77cb6908be860865$0$$16$24ee62740976ada0e7a41ade3552ee42", "1234567980"},
	{NULL}
};

int sappse_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int extra;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	if (atoi(p) != 1)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iterations
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt size
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res > 32)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iv size
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iv
		goto bail;
	if (hexlenl(p, &extra) > 32 * 2 || extra)
		goto bail;
	if (*p && !ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // encrypted_pin_length
		goto bail;
	if (!isdec(p))
		goto bail;
	res = atoi(p);
	if (res > 128)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // encrypted_pin
		goto bail;
	if (hexlenl(p, &extra) != res * 2 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

void *sappse_common_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;

	memset(&cs, 0, sizeof(cs));
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	p = strtokm(NULL, "$");
	cs.salt_size = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.salt_size; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cs.encrypted_pin_size = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.encrypted_pin_size; i++)
		cs.encrypted_pin[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];

	MEM_FREE(keeptr);

	return (void *)&cs;
}

unsigned int sappse_iteration_count(void *salt)
{
	struct custom_salt *cs = salt;

	return (unsigned int) cs->iterations;
}
