#include <string.h>
#include <ctype.h>

#include "arch.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "lastpass_cli_common.h"

struct fmt_tests lastpass_cli_tests[] = {
	/* LastPass CLI v1.2.1 */
	{"$lpcli$0$lulu@mailinator.com$1234$3fec6cd2d8c049cbafe9fa6a9343f42f$f21d8e60ad22db53033e431700fb5e0c", "Badpassword098765"},
	{"$lpcli$0$lulu@mailinator.com$1234$fbd97e7e14713363c5567bdc106bb1f4$75ebb9460f9852ccb2382029fe333867", "Password12345"},
	// Special case where iterations == 1
#ifndef HAVE_OPENCL
	{"$lpcli$0$lulu@mailinator.com$1$9611651d6cbe6ab1dfb035d3874bd803$68bbe1480410c03cc053662658884f2b", "Password12345"},
#endif
	{NULL}
};

int lastpass_cli_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;
	int type = 0;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* type */
		goto err;
	if (!isdec(p))
		goto err;
	type = atoi(p);
	if (type != 0)
		goto err;
	if (strlen(p) > 32)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* email */
		goto err;
	if (strlen(p) > 32)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* iterations */
		goto err;
	if (!isdec(p))
		goto err;
#ifdef HAVE_OPENCL
	if (atoi(p) <= 1)
		goto err;
#endif
	if ((p = strtokm(NULL, "$")) == NULL) /* iv */
		goto err;
	if (hexlenl(p, &extra) != 32 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* hash */
		goto err;
	if (hexlenl(p, &extra) != 32 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *lastpass_cli_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;

	p = strtokm(ctcopy, "$");
	p = strtokm(NULL, "$");
	strncpy((char*)cs.salt, p, 32);
	cs.salt_length = strlen((char*)p);
	p = strtokm(NULL, "$");
	cs.iterations = atoi(p);
	if (cs.iterations < 1)
		cs.iterations = 1;
	p = strtokm(NULL, "$");
	for (i = 0; i < 16; i++)
		cs.iv[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return (void *)&cs;
}

void *lastpass_cli_common_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		uint32_t dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

unsigned int lastpass_cli_common_iteration_count(void *salt)
{
        return ((struct custom_salt*)salt)->iterations;
}
