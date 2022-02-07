/*
 * Common code for the AxCrypt format.
 */

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "axcrypt_common.h"

int axcrypt_common_valid(char *ciphertext, struct fmt_main *self, int versions_supported)
{
	char *ctcopy, *keeptr, *p;
	int version, saltlen, wrappedkeylen;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;		/* skip over "$axcrypt$*" */
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* version */
		goto err;
	if (!isdec(p))
		goto err;
	version = atoi(p);
	if (version == 1) {
		saltlen = 16;
		wrappedkeylen = 24;
		if (versions_supported == 2)
			goto err;
	} else {
		if (versions_supported == 1)
			goto err;
		saltlen = 64;  // WrapSalt
		wrappedkeylen = 144;
	}
	if ((p = strtokm(NULL, "*")) == NULL)	/* iterations */
		goto err;
	if (!isdec(p))
		goto err;
	if (!atoi(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* salt */
		goto err;
	if (strlen(p) != saltlen * 2 || !ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* wrappedkey */
		goto err;
	if (strlen(p) != wrappedkeylen * 2 || !ishexlc(p))
		goto err;
	/* optional key-file following */

	/* AxCrypt 2.x handling */
	if (version == 2) {
		if ((p = strtokm(NULL, "*")) == NULL)
			goto err;
		if (!isdec(p))
			goto err;
		if ((p = strtokm(NULL, "*")) == NULL)
			goto err;
		if (strlen(p) != 32 * 2 || !ishexlc(p))
			goto err;
	}

	MEM_FREE(keeptr);
	return 1;
err:
	MEM_FREE(keeptr);
	return 0;
}

void *axcrypt_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;
	static struct custom_salt cs;
	static void *ptr;
	int saltlen = 0;
	int wrappedkeylen;

	memset(&cs, 0, sizeof(cs));
	cs.keyfile = NULL;
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$axcrypt$*" */
	p = strtokm(ctcopy, "*");
	cs.version = atoi(p);

	if (cs.version == 1) {
		saltlen = 16;
		wrappedkeylen = 24;
	} else {
		saltlen = 64;  // WrapSalt
		wrappedkeylen = 144;
	}

	p = strtokm(NULL, "*");
	cs.key_wrapping_rounds = (uint32_t) atoi(p);

	p = strtokm(NULL, "*");
	for (i = 0; i < saltlen; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	p = strtokm(NULL, "*");
	for (i = 0; i < wrappedkeylen; i++)
		cs.wrappedkey[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	if (cs.version == 1) {
		/* if key-file present */
		if ((p = strtokm(NULL, "*")) != NULL) {
			cs.keyfile = (char*) mem_calloc_tiny(strlen(p)/2 + 1, sizeof(char));
			for (i = 0; i < strlen(p) / 2; i++)
				cs.keyfile[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
					+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
		}
	}

	if (cs.version == 2) {
		p = strtokm(NULL, "*");
		cs.deriv_iterations = atoi(p);
		p = strtokm(NULL, "*");

		for (i = 0; i < 32; i++)
			cs.deriv_salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16 + atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}

	MEM_FREE(keeptr);

	cs.dsalt.salt_cmp_offset = SALT_CMP_OFF(struct custom_salt, salt);
	cs.dsalt.salt_cmp_size = SALT_CMP_SIZE(struct custom_salt, salt, wrappedkey, 0);
	cs.dsalt.salt_alloc_needs_free = 0;

	ptr = mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	memcpy(ptr, &cs, sizeof(struct custom_salt));

	return (void *) &ptr;
}

unsigned int axcrypt_iteration_count(void *salt)
{
	struct custom_salt *cur_salt = *(struct custom_salt **) salt;

	return cur_salt->key_wrapping_rounds;
}
