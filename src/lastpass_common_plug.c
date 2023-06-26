#include "arch.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "aes.h"
#include "lastpass_common.h"

struct fmt_tests lastpass_tests[] = {
	{"$lp$hackme@mailinator.com$6f5d8cec3615fc9ac7ba2e0569bce4f5", "strongpassword"},
	{"$lp$3$27c8641d7f5ab5985569d9d0b499b467", "123"},
	{"$lp$ninechars$d09153108a89347da5c97a4a18f91345", "PassWord"},
	{"$lp$anicocls$764b0f54528eb4a4c93aab1b18af28a5", ""},
	/* Three hashes from LastPass v3.3.4 for Firefox on Linux */
	{"$lp$lulu@mailinator.com$5000$d8d1e25680b3d9f73489d5769ac3a9c1", "Openwall123"},
	{"$lp$lulu@mailinator.com$5000$2edc5742660ddd3e26ce52aeca993531", "Password123"},
	{"$lp$lulu@mailinator.com$1234$6e5cea4fbde80072ffc736bfa8c88730", "Password123"},
	{NULL}
};

int lastpass_common_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p;
	int extra;
	int have_iterations = 0;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)	/* email */
		goto err;
	if (strlen(p) > 32)
		goto err;
	/* hack to detect if iterations is present in hash */
	if ((p = strtokm(NULL, "$")) == NULL)	/* iterations or hash */
		goto err;
	if (strlen(p) < 24) {
		have_iterations = 1;
	}
	if (have_iterations) {
		if ((p = strtokm(NULL, "$")) == NULL)	/* hash */
			goto err;
	}
	if (hexlenl(p, &extra) != 32 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

void *lastpass_common_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	static struct custom_salt cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;
	p = strtokm(ctcopy, "$");
	strncpy((char*)cs.salt, p, 32);
	cs.salt_length = strlen((char*)p);
	p = strtokm(NULL, "$");
	if (strlen(p) < 24) { // new hash format
		cs.iterations = atoi(p);
	} else {
		cs.iterations = 500; // default iterations value
	}

	MEM_FREE(keeptr);
	return (void *)&cs;
}

void *lastpass_common_get_binary(char *ciphertext)
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

unsigned int lastpass_common_iteration_count(void *salt)
{
        return ((struct custom_salt*)salt)->iterations;
}
