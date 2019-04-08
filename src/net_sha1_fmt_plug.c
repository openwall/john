/* Cracker for "Keyed SHA1" network authentication hashes.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Added linkage to dynamic (type dynamic_40) for any salt 230 bytes or less,
 * by Jim Fougeron.  Any salts > 239 bytes will still be handled by this full
 * format.  dynamic is limited to 256 bytes, which 'should' get us 240 bytes
 * of salt.  I think we might be able to get 239 bytes (due to a few issues).
 * 240 byte salts fail. So, for peace of mind, I am limiting to 230 byte salts
 * within dynamic.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_netsha1;
#elif FMT_REGISTERS_H
john_register_one(&fmt_netsha1);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE 2048 // XXX
#endif
#endif

#include "formats.h"
#include "dynamic.h"
#include "sha.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"


#define FORMAT_LABEL            "net-sha1"
#define FORMAT_NAME             "\"Keyed SHA1\" BFD"
#define FORMAT_TAG              "$netsha1$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7

#define PLAINTEXT_LENGTH        20  // get this right ;)
#define BINARY_SIZE             20
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              MEM_ALIGN_WORD
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define MAX_SALT_LEN			1500

static struct fmt_tests tests[] = {
	/* Real hashes from Cisco routers ;) */
	{"$netsha1$20440a340000000100000000000f4240000f424000000000051c010000000001$709d3307304d790f58bf0a3cefd783b438408996", "password12345"},
	{"$netsha1$20440a340000000100000000000f4240000f424000000000051c010000000002$94bce4d9084199508669b39f044064082a093de3", "password12345"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static void get_ptr();
static void init(struct fmt_main *self);
static void done(void);

#define MAGIC 0xfe5aa5ef

static struct custom_salt {
	uint32_t magic;
	int length;
	unsigned char salt[MAX_SALT_LEN]; // fixed size, but should be OK
} *cur_salt;
static int dyna_salt_seen=0;
static char Conv_Buf[300]; // max salt length we will pass to dyna is 230.  300 is MORE than enough.
static struct fmt_main *pDynamicFmt, *pNetSha1_Dyna;

/* this function converts a 'native' net-sha1 signature string into a $dynamic_40$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	char *cp, *cp2;

	if (text_in_dynamic_format_already(pDynamicFmt, ciphertext))
		return ciphertext;

	cp = strchr(&ciphertext[2], '$');
	if (!cp)
		return "*";
	cp2 = strchr(&cp[1], '$');
	if (!cp2)
		return "*";
	snprintf(Buf, sizeof(Conv_Buf), "$dynamic_40$%s$HEX%*.*s", &cp2[1], (int)(cp2-cp), (int)(cp2-cp), cp);
	return Buf;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q = NULL;
	int len;

	p = ciphertext;

	if (!strncmp(p, FORMAT_TAG, TAG_LENGTH))
		p += TAG_LENGTH;

	q = strrchr(ciphertext, '$');
	if (!q)
		return 0;
	q = q + 1;
	if ((q - p - 1) > MAX_SALT_LEN * 2)
		return 0;

	len = strspn(q, HEXCHARS_lc);
	if (len != BINARY_SIZE * 2 || len != strlen(q)) {
		get_ptr();
		return pDynamicFmt->methods.valid(ciphertext, pDynamicFmt);
	}

	if (strspn(p, HEXCHARS_lc) != q - p - 1)
		return 0;

	return 1;
}

static void *get_salt(char *ciphertext)
{
	static char *pBuf=NULL;
	struct custom_salt *cs;
	char *orig_ct = ciphertext;
	int i, len;

	if (!pBuf) pBuf = (char *)mem_alloc_tiny(sizeof(struct custom_salt), MEM_ALIGN_WORD);
	cs = (struct custom_salt*) pBuf;
	memset(cs, 0, sizeof(*cs));

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	len = (strrchr(ciphertext, '$') - ciphertext) / 2;

	for (i = 0; i < len; i++)
		cs->salt[i] = (atoi16[ARCH_INDEX(ciphertext[2 * i])] << 4) |
			atoi16[ARCH_INDEX(ciphertext[2 * i + 1])];

	if (len < 230) {
		// return our memset buffer (putting the dyna salt pointer into it).
		// This keeps the 'pre-cleaned salt() warning from hitting this format)
		//return pDynamicFmt->methods.salt(Convert(Conv_Buf, orig_ct));
		memcpy((char*)cs, pDynamicFmt->methods.salt(Convert(Conv_Buf, orig_ct)), pDynamicFmt->params.salt_size);
		dyna_salt_seen=1;
		return cs;
	}
	cs->magic = MAGIC;
	cs->length = len;
	return cs;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;
	if (text_in_dynamic_format_already(pDynamicFmt, ciphertext)) {
		unsigned char *cp = pDynamicFmt->methods.binary(ciphertext);
		memset(out, 0, sizeof(buf.c));
		memcpy(out, cp, pDynamicFmt->params.binary_size); // binary size is 16
		return out;
	}
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
	get_ptr();
	if (cur_salt->magic != MAGIC) {
		pDynamicFmt->methods.set_salt(salt);
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	if (cur_salt->magic != MAGIC) {
		return pDynamicFmt->methods.crypt_all(pcount, salt);
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		SHA_CTX ctx;

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, cur_salt->salt, cur_salt->length);
		SHA1_Update(&ctx, saved_key[index], PLAINTEXT_LENGTH);
		SHA1_Final((unsigned char*)crypt_out[index], &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	if (cur_salt->magic != MAGIC) {
		return pDynamicFmt->methods.cmp_all(binary, count);
	}
	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	if (cur_salt->magic != MAGIC) {
		return pDynamicFmt->methods.cmp_one(binary, index);
	}
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void netsha1_set_key(char *key, int index)
{
	if (dyna_salt_seen)
		pDynamicFmt->methods.set_key(key, index);
	/* strncpy will pad with zeros, which is needed */
	strncpy(saved_key[index], key, sizeof(saved_key[0]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static char *prepare(char *fields[10], struct fmt_main *self) {
	static char buf[sizeof(cur_salt->salt)*2+TAG_LENGTH+1];
	char *hash = fields[1];
	if (strncmp(hash, FORMAT_TAG, TAG_LENGTH) && valid(hash, self)) {
		get_ptr();
		if (text_in_dynamic_format_already(pDynamicFmt, hash))
			return hash;
		sprintf(buf, "%s%s", FORMAT_TAG, hash);
		return buf;
	}
	return hash;
}

struct fmt_main fmt_netsha1 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		netsha1_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

static void get_ptr() {
	if (!pDynamicFmt) {
		char *Buf;
		pNetSha1_Dyna = mem_alloc_tiny(sizeof(fmt_netsha1), 16);
		memcpy(pNetSha1_Dyna, &fmt_netsha1, sizeof(fmt_netsha1));

		pDynamicFmt = dynamic_THIN_FORMAT_LINK(pNetSha1_Dyna, Convert(Conv_Buf, tests[1].ciphertext), "net-sha1", 0);
		fmt_netsha1.params.min_keys_per_crypt = pDynamicFmt->params.min_keys_per_crypt;
		fmt_netsha1.params.max_keys_per_crypt = pDynamicFmt->params.max_keys_per_crypt;
		Buf = mem_alloc_tiny(strlen(fmt_netsha1.params.algorithm_name) + 4 + strlen("dynamic_40") + 1, 1);
		sprintf(Buf, "%s or %s", fmt_netsha1.params.algorithm_name, "dynamic_40");
		fmt_netsha1.params.algorithm_name = Buf;
		//pDynamicFmt->methods.init(pDynamicFmt);
	}
}

static void init(struct fmt_main *self)
{
	// We have to allocate our dyna_40 object first, because we get 'modified' min/max counts from there.
	get_ptr();
	if (self->private.initialized == 0) {
		pDynamicFmt = dynamic_THIN_FORMAT_LINK(pNetSha1_Dyna, Convert(Conv_Buf, tests[1].ciphertext), "net-sha1", 1);
		self->private.initialized = 1;
	}
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	pDynamicFmt->methods.done();
}

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */
