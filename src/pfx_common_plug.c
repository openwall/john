/*
 * This software is
 * Copyright (c) 2016, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2019, magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#include "pfx_common.h"

int pfx_valid(char *ciphertext, struct fmt_main *self)
{
	char *p = ciphertext, *ctcopy, *keeptr;
	int mac_algo, saltlen, hashhex, extra;

	if (strncasecmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // mac_algo
		goto bail;
	if (!isdec(p))
		goto bail;
	mac_algo = atoi(p);
	//if (mac_algo == 0)
	//	hashhex = 40;	// for sha0  (Note, not handled by ans1crypt.py)
	if (mac_algo == 1)	 // 1 -> SHA1, 256 -> SHA256
		hashhex = 40;		// hashhex is length of hex string of hash.
//	else if (mac_algo == 2)	// mdc2  (Note, not handled by ans1crypt.py)
//		hashhex = 32;
//	else if (mac_algo == 4)	// md4  (Note, not handled by ans1crypt.py)
//		hashhex = 32;
//	else if (mac_algo == 5)	//md5  (Note, not handled by ans1crypt.py)
//		hashhex = 32;
//	else if (mac_algo == 160)	//ripemd160  (Note, not handled by ans1crypt.py)
//		hashhex = 40;
	else if (!strstr(self->params.label, "-opencl") && mac_algo == 224)
		hashhex = 56;
	else if (mac_algo == 256)
		hashhex = 64;
	else if (!strstr(self->params.label, "-opencl") && mac_algo == 384)
		hashhex = 96;
	else if (mac_algo == 512)
		hashhex = 128;
	else
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // key_length
		goto bail;
	if (!isdec(p))
		goto bail;
	if (atoi(p) != (hashhex>>1))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // iteration_count
		goto bail;
	if (!isdec(p))
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // saltlen
		goto bail;
	if (!isdec(p))
		goto bail;
	saltlen = atoi(p);
	if (saltlen > 20)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // salt
		goto bail;
	if (hexlenl(p, &extra) != saltlen * 2 || extra)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // data
		goto bail;
	if (hexlenl(p, &extra) > MAX_DATA_LENGTH * 2 || extra)
		goto bail;
	if ((p = strtokm(NULL, "$")) == NULL) // stored_hmac (not stored in salt)
		goto bail;
	if (hexlenl(p, &extra) != hashhex || extra)
		goto bail;
	if (strtokm(NULL, "$")) // no more fields
		goto bail;

	MEM_FREE(keeptr);
	return 1;

bail:
	MEM_FREE(keeptr);
	return 0;
}

void *pfx_common_get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p = ciphertext, *ctcopy, *keeptr;
	memset(&cs, 0, sizeof(cs));

	ctcopy = xstrdup(ciphertext);
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
	struct custom_salt *my_salt = salt;

	return (unsigned int) my_salt->mac_algo;
}

unsigned int pfx_iteration_count(void *salt)
{
	struct custom_salt *cs = (struct custom_salt*)salt;

	return cs->iteration_count;
}
