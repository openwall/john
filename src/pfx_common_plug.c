#include "pfx_common.h"

void *pfx_common_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	memset(&cs, 0, sizeof(cs));

	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.mac_algo = atoi(p);
	p = strtokm(NULL, "$");
	cs.key_length = atoi(p);
	p = strtokm(NULL, "$");
	cs.iteration_count = atoi(p);
	p = strtokm(NULL, "$");
	cs.saltlen = atoi(p);
	p = strtokm(NULL, "$");
	for (i = 0; i < cs.saltlen; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");
	cs.data_length = hexlenl(p, 0) / 2;
	for (i = 0; i < cs.data_length; i++)
		cs.data[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");

	MEM_FREE(keeptr);

	return (void *)&cs;
}

// we only grab first 20 bytes of the hash, but that is 'good enough'.
// it makes a lot of other coding more simple.
void *pfx_common_get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	int i;
	char *p;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

unsigned int pfx_get_mac_type(void *salt)
{
	struct custom_salt *my_salt;

	my_salt = salt;
	return (unsigned int) my_salt->mac_algo;
}
