/* Cracker for RIPv2 MD5 authentication hashes.
 *
 * This software is Copyright (c) 2013, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Added linkage to dynamic (type dynamic_39) for any salt 230 bytes or less,
 * by Jim Fougeron.  Any salts > 239 bytes will still be handled by this full
 * format.  dynamic is limited to 256 bytes, which 'should' get us 240 bytes
 * of salt.  I think we might be able to get 239 bytes (due to a few issues).
 * 240 byte salts fail. So, for peace of mind, I am limiting to 230 byte salts
 * within dynamic.  This is the FIRST format that is hybrid fat-thin.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_netmd5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_netmd5);
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
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"


#define FORMAT_LABEL            "net-md5"
#define FORMAT_NAME             "\"Keyed MD5\" RIPv2, OSPF, BGP, SNMPv2"
#define FORMAT_TAG              "$netmd5$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
// RIPv2 truncates (or null pads) passwords to length 16
#define PLAINTEXT_LENGTH        16
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              MEM_ALIGN_WORD
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define MAX_SALT_LEN			1500

static struct fmt_tests tests[] = {
	/* RIPv2 MD5 authentication hashes */
	{           "02020000ffff0003002c01145267d48d000000000000000000020000ac100100ffffff000000000000000001ffff0001$1e372a8a233c6556253a0909bc3dcce6", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d48f000000000000000000020000ac100100ffffff000000000000000001ffff0001$ed9f940c3276afcc06d15babe8a1b61b", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d490000000000000000000020000ac100100ffffff000000000000000001ffff0001$c9f7763f80fcfcc2bbbca073be1f5df7", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d49a000000000000000000020000ac100200ffffff000000000000000001ffff0001$3f6a72deeda200806230298af0797997", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d49b000000000000000000020000ac100200ffffff000000000000000001ffff0001$b69184bacccc752cadf78cac455bd0de", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267d49d000000000000000000020000ac100100ffffff000000000000000001ffff0001$6442669c577e7662188865a54c105d0e", "quagga"},
	{FORMAT_TAG "02020000ffff0003002c01145267e076000000000000000000020000ac100200ffffff000000000000000001ffff0001$4afe22cf1750d9af8775b25bcf9cfb8c", "abcdefghijklmnop"},
	{FORMAT_TAG "02020000ffff0003002c01145267e077000000000000000000020000ac100200ffffff000000000000000001ffff0001$326b12f6da03048a655ea4d8f7e3e123", "abcdefghijklmnop"},
	{FORMAT_TAG "02020000ffff0003002c01145267e2ab000000000000000000020000ac100100ffffff000000000000000001ffff0001$ad76c40e70383f6993f54b4ba6492a26", "abcdefghijklmnop"},
	/* OSPFv2 MD5 authentication hashes */
	{"$netmd5$0201002cac1001010000000000000002000001105267ff8fffffff00000a0201000000280000000000000000$445ecbb27272bd791a757a6c85856150", "abcdefghijklmnop"},
	{FORMAT_TAG "0201002cac1001010000000000000002000001105267ff98ffffff00000a0201000000280000000000000000$d4c248b417b8cb1490e02c5e99eb0ad1", "abcdefghijklmnop"},
	{FORMAT_TAG "0201002cac1001010000000000000002000001105267ffa2ffffff00000a0201000000280000000000000000$528d9bf98be8213482af7295307625bf", "abcdefghijklmnop"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
static void get_ptr();
static void init(struct fmt_main *self);
static void done(void);

#define MAGIC 0xfe5dd5ef

static struct custom_salt {
	uint32_t magic;
	int length;
	unsigned char salt[MAX_SALT_LEN]; // fixd len, but should be OK
} *cur_salt;
static int dyna_salt_seen=0;
static char Conv_Buf[300]; // max salt length we will pass to dyna is 230.  300 is MORE than enough.
static struct fmt_main *pDynamicFmt, *pNetMd5_Dyna;

/* this function converts a 'native' net-md5 signature string into a $dynamic_39$ syntax string */
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
	snprintf(Buf, sizeof(Conv_Buf), "$dynamic_39$%s$HEX%*.*s", &cp2[1], (int)(cp2-cp), (int)(cp2-cp), cp);
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
	if (text_in_dynamic_format_already(pDynamicFmt, ciphertext))
		// returns proper 16 bytes, so we do not need to copy into our buffer.
		return pDynamicFmt->methods.binary(ciphertext);
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
	int index = 0;

	if (cur_salt->magic != MAGIC) {
		return pDynamicFmt->methods.crypt_all(pcount, salt);
	}
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		MD5_CTX ctx;

		MD5_Init(&ctx);
		MD5_Update(&ctx, cur_salt->salt, cur_salt->length);
		MD5_Update(&ctx, saved_key[index], PLAINTEXT_LENGTH);
		MD5_Final((unsigned char*)crypt_out[index], &ctx);
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

static void netmd5_set_key(char *key, int index)
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
		if (strlen(hash) + TAG_LENGTH + 1 > sizeof(buf))
			return hash;
		sprintf(buf, "%s%s", FORMAT_TAG, hash);
		return buf;
	}
	return hash;
}

struct fmt_main fmt_netmd5 = {
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
		netmd5_set_key,
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
		pNetMd5_Dyna = mem_alloc_tiny(sizeof(fmt_netmd5), 16);
		memcpy(pNetMd5_Dyna, &fmt_netmd5, sizeof(fmt_netmd5));

		pDynamicFmt = dynamic_THIN_FORMAT_LINK(pNetMd5_Dyna, Convert(Conv_Buf, tests[1].ciphertext), "net-md5", 0);
		fmt_netmd5.params.min_keys_per_crypt = pDynamicFmt->params.min_keys_per_crypt;
		fmt_netmd5.params.max_keys_per_crypt = pDynamicFmt->params.max_keys_per_crypt;
		Buf = mem_alloc_tiny(strlen(fmt_netmd5.params.algorithm_name) + 4 + strlen("dynamic_39") + 1, 1);
		sprintf(Buf, "%s or %s", fmt_netmd5.params.algorithm_name, "dynamic_39");
		fmt_netmd5.params.algorithm_name = Buf;
		//pDynamicFmt->methods.init(pDynamicFmt);
	}
}

static void init(struct fmt_main *self)
{
	// We have to allocate our dyna_39 object first, because we get 'modified' min/max counts from there.
	get_ptr();
	if (self->private.initialized == 0) {
		pDynamicFmt = dynamic_THIN_FORMAT_LINK(pNetMd5_Dyna, Convert(Conv_Buf, tests[1].ciphertext), "net-md5", 1);
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
