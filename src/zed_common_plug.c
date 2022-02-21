/*
 * This software is Copyright (c) 2019 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "zed_common.h"

struct fmt_tests zed_tests[] = {
	{"$zed$2$22$200000$4d05362c7ac3f518$a649427303fae36e", "Azertyui"},
	{"$zed$2$22$200000$5f5b6e37dcd7d290$08b52fbdff4354f8", "Azertyui"},
	/*
	 * UTF-8 encoded passwords (index 2/3). These must be last - they
	 * will be nulled unless we're running UTF-8 or CP1252.
	 */
	{"$zed$1$21$200000$d58a3e9706afdd23$875b114ea259897d", "Op€nwal£"},
	{"$zed$2$22$200000$bd2d2407f012111e$e1ae10351e9ec1e6", "Op€nwal£"},
	{NULL},
};

int zed_valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int version, algo, extra;

	if (strncasecmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // version
		goto bail;
	if (!isdec(p))
		goto bail;
	version = atoi(p);
	if (version < 1 || version > 2)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // algo
		goto bail;
	if (!isdec(p))
		goto bail;
	algo = atoi(p);
	if (algo < 21 || algo > 22) // 21 = SHA-1, 22 = SHA-256
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iteration_count
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) != 16 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // verifier
		goto bail;
	if (hexlenl(p, &extra) != 16 || extra)
		goto bail;
	if (!ishexlc(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) != NULL) // trailing data
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

void *zed_common_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;

	memset(&cs, 0, sizeof(cs));
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	p = strtokm(ctcopy, "$"); // ver
	p = strtokm(NULL, "$"); // algo
	cs.algo = atoi(p);
	p = strtokm(NULL, "$"); // iterations
	cs.iteration_count = atoi(p);
	p = strtokm(NULL, "$"); // salt
	for (i = 0; i < salt_len; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2*i])] << 4) | atoi16[ARCH_INDEX(p[2*i+1])];
	p = strtokm(NULL, "$");

	MEM_FREE(keeptr);

	return (void *)&cs;
}

void *zed_common_get_binary(char *ciphertext)
{
	static unsigned char out[BINARY_SIZE];
	int i;
	char *p;

	memset(&out, 0, sizeof(out));
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE && *p; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

unsigned int zed_get_mac_type(void *salt)
{
	struct custom_salt *my_salt = salt;

	return (unsigned int) my_salt->algo;
}

unsigned int zed_iteration_count(void *salt)
{
	struct custom_salt *cs = (struct custom_salt*)salt;

	return cs->iteration_count;
}

int zed_salt_hash(void *salt)
{
	unsigned char *s = (unsigned char*)salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < sizeof(struct custom_salt); i++)
		hash = ((hash << 5) + hash) ^ s[i];

	return hash & (SALT_HASH_SIZE - 1);
}
