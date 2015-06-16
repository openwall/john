/*
 * Cracker for MD5 based authentication in VTP.
 *
 * This software is Copyright (c) 2014 Alexey Lapitsky <lex at
 * realisticgroup.com> and Dhiru Kholia <dhiru at openwall.com>, and it is
 * hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without#
 * modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_vtp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_vtp);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
// Tuned on core i7 4-core HT
// 64  - 19k
// 128 - 27k
// 256 - 30.5k  ** chosen **
// 512 - 30.5k
// 1k  - 28.5k
// 2k  - 28.5k  (times wobble)
#ifndef OMP_SCALE
#define OMP_SCALE 256
#endif
#endif

#include "arch.h"
#include "md5.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "params.h"
#include "options.h"
#include "memdbg.h"

#define FORMAT_LABEL            "vtp"
#define FORMAT_NAME             "\"MD5 based authentication\" VTP"
#define FORMAT_TAG              "$vtp$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "MD5 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0
#define PLAINTEXT_LENGTH        55 // keep under 1 MD5 block AND this is now tied into logic in vtp_secret_derive()
#define BINARY_SIZE             16
#define BINARY_ALIGN            sizeof(ARCH_WORD_32)
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(int)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define HEXCHARS                "0123456789abcdef"

static struct fmt_tests tests[] = {
	{"$vtp$2$196$14000107000105dc000186a164656661756c740014000105000505dc000186a56368656e6100000010000103000605dc000186a6666666001800020c03ea05dc00018a8a666464692d64656661756c743000030d03eb117800018a8b74726372662d64656661756c7400000001010ccc040103ed0701000208010007090100072000040f03ec05dc00018a8c666464696e65742d64656661756c7400030100012400050d03ed117800018a8d74726272662d64656661756c740000000201000f03010002$80$0201010c646f6d61696e313233343536000000000000000000000000000000000000000000000015000000003134313030393134333631376010913064949d6f47a53b2ad68ef06b0000000106010002$6010913064949d6f47a53b2ad68ef06b", "123"},
	{"$vtp$1$184$14000107000105dc000186a164656661756c740014000105000505dc000186a568656c6c6f0000002000020c03ea05dc00018a8a666464692d64656661756c7401010000040100002800031203eb05dc00018a8b746f6b656e2d72696e672d64656661756c74000001010000040100002400040f03ec05dc00018a8c666464696e65742d64656661756c740002010000030100012400050d03ed05dc00018a8d74726e65742d64656661756c740000000201000003010002$77$0101010c646f6d61696e313233343536000000000000000000000000000000000000000000000010000000003134313030393134313432372212dd93025abc600281d74ddda8a21c0101000200$2212dd93025abc600281d74ddda8a21c", "123"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *saved_len;
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

/* VTP summary advertisement packet, partially based on original Yersinia code */
typedef struct {
    unsigned char version;
    unsigned char code;
    unsigned char followers;
    unsigned char domain_name_length;
    unsigned char domain_name[32];  // zero padded
    uint32_t revision;  // 4 bytes
    uint32_t updater;   // 4 bytes
    unsigned char update_timestamp[12]; // zero'ed during MAC calculations
    unsigned char md5_checksum[16];
} vtp_summary_packet;

static  struct custom_salt {
	int length;
	vtp_summary_packet vsp;
	int vlans_data_length;
	unsigned char vlans_data[8192];
	int salt_length;
	unsigned char salt[2048];
	int trailer_length;
	int version;
	unsigned char trailer_data[64];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_num_threads();

	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
		self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *ptrkeep;
	int res;
	p = ciphertext;
	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return 0;

	ptrkeep = strdup(ciphertext);
	p = &ptrkeep[TAG_LENGTH];

	if ((p = strtokm(p, "$")) == NULL) /* version */
		goto err;
	res = atoi(p);
	if (res != 1  && res != 2)  // VTP version 3 support is pending
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL)  /* vlans len */
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)  /* vlans data */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishex(p))
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL)  /* salt len */
		goto err;
	res = atoi(p);
	if ((p = strtokm(NULL, "$")) == NULL)  /* salt */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishex(p))
		goto err;

	if (((atoi16[ARCH_INDEX(p[6])]<<4)|atoi16[ARCH_INDEX(p[7])]) >
		sizeof(cur_salt->vsp.domain_name))
		goto err;

	if ((p = strtokm(NULL, "$")) == NULL)  /* hash */
		goto err;
	if (strlen(p) != BINARY_SIZE * 2)
		goto err;
	if (!ishex(p))
		goto err;

	MEM_FREE(ptrkeep);
	return 1;
err:
	MEM_FREE(ptrkeep);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	int i;
	char *p, *q;
	memset(&cs, 0, SALT_SIZE);

	if (!strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		ciphertext += TAG_LENGTH;

	p = ciphertext;
	cs.version = atoi(p);
	q = p + 2;
	cs.vlans_data_length = atoi(q);
	q = strchr(q, '$') + 1;  // at vlans_data

	for (i = 0; i < cs.vlans_data_length; i++)
		cs.vlans_data[i] = (atoi16[ARCH_INDEX(q[2 * i])] << 4) |
			atoi16[ARCH_INDEX(q[2 * i + 1])];

	q = strchr(q, '$') + 1;  // at salt_length
	cs.salt_length = atoi(q);
	q = strchr(q, '$') + 1;  // at salt
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(q[2 * i])] << 4) |
			atoi16[ARCH_INDEX(q[2 * i + 1])];

	if (cs.salt_length > 72) { /* we have trailing bytes */
		cs.trailer_length = cs.salt_length - 72;
		memcpy(cs.trailer_data, cs.salt + 72, cs.trailer_length);
	}

	cs.vsp.version = cs.salt[0];  // based on Wireshark
	cs.vsp.code = cs.salt[1];

	// Zero out various fields for MAC calculation
	cs.vsp.followers = 0;
	memset(cs.vsp.update_timestamp, 0, 12);
	memset(cs.vsp.md5_checksum, 0, 16);

	// fill rest of the data
	cs.vsp.domain_name_length = cs.salt[3];
	if (cs.vsp.domain_name_length > sizeof(cs.vsp.domain_name))
		cs.vsp.domain_name_length = sizeof(cs.vsp.domain_name);
	memcpy(cs.vsp.domain_name, cs.salt + 4, cs.vsp.domain_name_length);
	memcpy((unsigned char*)&cs.vsp.revision, cs.salt + 36, 4);
	memcpy((unsigned char*)&cs.vsp.updater,  cs.salt + 36 + 4, 4);

	return (void*)&cs;
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
	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < BINARY_SIZE; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void vtp_secret_derive(char *password, int length, unsigned char *output)
{
#if 0
	/* old code kept as a easier to read view of what is being done */
	MD5_CTX ctx;
	unsigned char *cp, buf[64];
	unsigned int password_idx = 0;
	int i, j;

	if (length == 0)  {
		memset(output, 0, 16);
		return;
	}

	MD5_Init(&ctx);
	for(i = 0; i < 1563; i++) { /* roughly 1 MB */
		cp = buf;
			for (j = 0; j < 64; j++) /* treat password as a cyclic generator */
				*cp++ = password[password_idx++ % length];
		MD5_Update(&ctx, buf, 64);
	}
	MD5_Final(output, &ctx);
#else
	// Speed went from 8k to 28k.  I think it should be VERY easy to add SIMD code here.
	// That would gain us another 4x or so speed.  TODO for someone to play with ;)
	MD5_CTX ctx;
	unsigned char *cp, buf[55][64];
	int bufs_used = 0, local_cnt = 0;
	int i, j;

	if (length == 0)  {
		memset(output, 0, 16);
		return;
	}
	cp = buf[bufs_used];
	/* treat password as a cyclic generator */
	for (;;) {
		/* note this WILL exit.  Modular math assures will do so in 'length' buffers or       */
		/* less. with PLAINTEXTLEN set to 55 bytes, we only need 55 buffers to assure a cycle */
		if (local_cnt + length <= 64) {
			memcpy(&cp[local_cnt], password, length);
			local_cnt += length;
			if (local_cnt == 64) {
				/* we ended a word at end of buffer, so we have the cycle */
				bufs_used++;
				break;
			}
		} else {
			int spill = local_cnt+length-64;
			memcpy(&cp[local_cnt], password, length-spill);
			cp = buf[++bufs_used];
			memcpy(cp, &password[length-spill], spill);
			local_cnt = spill;
		}
	}

	MD5_Init(&ctx);
	for(i = 0, j=0; i < 1563; ++i) { /* roughly 1 MB */
		MD5_Update(&ctx, buf[j++], 64);
		if (j == bufs_used)
			j = 0;
	}
	MD5_Final(output, &ctx);
#endif
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		MD5_CTX ctx;

		// space for (secret + SUMMARY ADVERTISEMENT + VLANS DATA + secret)
		unsigned char buf[8192] = {0};
		int offset = 0;

		// derive and append "secret"
		unsigned char secret[16];
		vtp_secret_derive(saved_key[index], saved_len[index], secret);
		memcpy(buf, secret, 16);
		offset = offset + 16;

		// append vtp_summary_packet
		memcpy(buf + offset, &cur_salt->vsp, sizeof(vtp_summary_packet));
		offset = offset + sizeof(vtp_summary_packet);

		// add trailing bytes (for VTP version >= 2)
		if (cur_salt->version != 1) {
			memcpy(buf + offset, cur_salt->trailer_data, cur_salt->trailer_length);
			offset += cur_salt->trailer_length;
		}

		// append vlans_data
		memcpy(buf + offset, cur_salt->vlans_data, cur_salt->vlans_data_length);
		offset += cur_salt->vlans_data_length;

		// append "secret" again
		memcpy(buf + offset, secret, 16);
		offset += 16;

		MD5_Init(&ctx);
		MD5_Update(&ctx, buf, offset);
		MD5_Final((unsigned char*)crypt_out[index], &ctx);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
		if (((ARCH_WORD_32*)binary)[0] == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void vtp_set_key(char *key, int index)
{
	saved_len[index] = strlen(key);

	/* strncpy will pad with zeros, which is needed */
	strncpy(saved_key[index], key, sizeof(saved_key[0]));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_vtp = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		vtp_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif
