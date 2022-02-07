/*
 * MS Office 97-2003 cracker patch for JtR. Hacked together during May of
 * 2012 by Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2014-2019, magnum
 * Copyright (c) 2009, David Leblanc (http://offcrypto.codeplex.com/)
 *
 * License: Microsoft Public License (MS-PL)
 */

#define OO_COMMON
#include "oldoffice_common.h"
#include "logger.h"
#include "john.h"

int *oo_cracked;
custom_salt *oo_cur_salt;

static struct {
	int ct_hash;
	unsigned char mitm[10];
} mitm_catcher;

/* Based on ldr_cracked_hash from loader.c */
#define HASH_LOG 30
#define HASH_SIZE (1 << HASH_LOG)
static int hex_hash(char *ciphertext)
{
	unsigned int hash, extra;
	unsigned char *p = (unsigned char *)ciphertext;

	hash = p[0] | 0x20; /* ASCII case insensitive */
	if (!hash)
		goto out;
	extra = p[1] | 0x20;
	if (!extra)
		goto out;

	p += 2;
	while (*p) {
		hash <<= 1; extra <<= 1;
		hash += p[0] | 0x20;
		if (!p[1]) break;
		extra += p[1] | 0x20;
		p += 2;
		if (hash & 0xe0000000) {
			hash ^= hash >> HASH_LOG;
			extra ^= extra >> (HASH_LOG - 1);
			hash &= HASH_SIZE - 1;
		}
	}

	hash -= extra;
	hash ^= extra << (HASH_LOG / 2);
	hash ^= hash >> HASH_LOG;
	hash &= HASH_SIZE - 1;
out:
	return hash;
}

int oldoffice_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int type, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LEN))
		return 0;
	if (strlen(ciphertext) > CIPHERTEXT_LENGTH)
		return 0;
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += TAG_LEN;
	if (!(ptr = strtokm(ctcopy, "*"))) /* type */
		goto error;
	type = atoi(ptr);
	if (type < 0 || type > 5)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* salt */
		goto error;
	if (hexlen(ptr, &extra) != 32 || extra)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier */
		goto error;
	if (hexlen(ptr, &extra) != 32 || extra)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* verifier hash */
		goto error;
	if (type < 3 && (hexlen(ptr, &extra) != 32 || extra))
		goto error;
	else if (type >= 3 && (hexlen(ptr, &extra) != 40 || extra))
		goto error;
	/* Optional extra data field for avoiding FP */
	if (type == 3 && (ptr = strtokm(NULL, "*"))) {
		if (hexlen(ptr, &extra) != 64 || extra)
			goto error;
	}
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

/* uid field may contain a meet-in-the-middle hash */
char *oldoffice_prepare(char *split_fields[10], struct fmt_main *self)
{
	if (split_fields[0] && oldoffice_valid(split_fields[0], self) &&
	    split_fields[1] &&
	    hexlen(split_fields[1], 0) == 10) {
		mitm_catcher.ct_hash = hex_hash(split_fields[0]);
		memcpy(mitm_catcher.mitm, split_fields[1], 10);
		return split_fields[0];
	}
	else if (oldoffice_valid(split_fields[1], self) && split_fields[2] &&
	         hexlen(split_fields[2], 0) == 10) {
		mitm_catcher.ct_hash = hex_hash(split_fields[1]);
		memcpy(mitm_catcher.mitm, split_fields[2], 10);
	}
	return split_fields[1];
}

char *oldoffice_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];
	char *p;
	int extra;

	strnzcpy(out, ciphertext, sizeof(out));
	strlwr(out);

	/* Drop legacy embedded MITM hash */
	if ((p = strrchr(out, '*')) && (hexlen(&p[1], &extra) == 10 || extra))
		*p = 0;
	return out;
}

void *oldoffice_get_binary(char *ciphertext)
{
	static fmt_data data;
	binary_blob *blob;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i, type;

	data.flags = FMT_DATA_TINY;
	data.size = sizeof(binary_blob);

	blob = (data.flags == FMT_DATA_TINY) ?
		mem_alloc_tiny(data.size, BINARY_ALIGN) : mem_alloc(data.size);
	data.blob = blob;

	memset(blob, 0, sizeof(binary_blob));

	ctcopy += TAG_LEN;	/* skip over "$oldoffice$" */
	p = strtokm(ctcopy, "*");
	type = atoi(p);
	p = strtokm(NULL, "*");
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		blob->verifier[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		blob->verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	if (type >= 3) {
		for (; i < 20; i++)
			blob->verifierHash[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	}
	if (type == 3 && (p = strtokm(NULL, "*"))) { /* Type 3 extra data */
		blob->has_extra = 1;
		for (i = 0; i < 32; i++)
			blob->extra[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
				+ atoi16[ARCH_INDEX(p[i * 2 + 1])];
	} else if (hex_hash(ciphertext) == mitm_catcher.ct_hash) {
		blob->has_mitm = 1;
		for (i = 0; i < 5; i++)
			blob->mitm[i] = atoi16[ARCH_INDEX(mitm_catcher.mitm[i * 2])] * 16
				+ atoi16[ARCH_INDEX(mitm_catcher.mitm[i * 2 + 1])];
		if (!ldr_in_pot && !bench_or_test_running && john_main_process) {
			log_event("- Using MITM key %02x%02x%02x%02x%02x for %s",
			          blob->mitm[0], blob->mitm[1], blob->mitm[2], blob->mitm[3], blob->mitm[4], ciphertext);
			blob->mitm_reported = 1;
		}
	}

	MEM_FREE(keeptr);
	return &data;
}

void *oldoffice_get_salt(char *ciphertext)
{
	static custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, sizeof(cs));
	ctcopy += TAG_LEN;	/* skip over "$oldoffice$" */
	p = strtokm(ctcopy, "*");
	cs.type = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < 16; i++)
		cs.salt[i] = atoi16[ARCH_INDEX(p[i * 2])] * 16
			+ atoi16[ARCH_INDEX(p[i * 2 + 1])];

	if (cs.type == 5 && !ldr_in_pot) {
		static int warned;

		if (john_main_process && !warned++) {
			fprintf(stderr, "Note: The support for OldOffice type 5 is experimental and may be incorrect.\n");
			fprintf(stderr, "      For latest news see https://github.com/openwall/john/issues/4705\n");
		}
	}

	MEM_FREE(keeptr);

	return &cs;
}

int oldoffice_cmp_one(void *binary, int index)
{
	binary_blob *cur_binary = ((fmt_data*)binary)->blob;

	if (!cur_binary->mitm_reported && oo_cracked[index] && oo_cur_salt->type < 4 &&
	    !cur_binary->has_extra && !bench_or_test_running) {
		unsigned char *cp, out[11];
		int i;

		cp = cur_binary->mitm;
		for (i = 0; i < 5; i++) {
			out[2 * i + 0] = itoa16[*cp >> 4];
			out[2 * i + 1] = itoa16[*cp & 0xf];
			cp++;
		}
		out[10] = 0;
		log_event("MITM key: %s", out);
		cur_binary->mitm_reported = 1;
	}
	return oo_cracked[index];
}

int oldoffice_cmp_exact(char *source, int index)
{
	return 1;
}

unsigned int oldoffice_hash_type(void *salt)
{
	return ((custom_salt*)salt)->type;
}

int oldoffice_salt_hash(void *salt)
{
	int salt32;

	memcpy(&salt32, ((custom_salt*)salt)->salt, sizeof(salt32));
	return salt32 & (SALT_HASH_SIZE - 1);
}
