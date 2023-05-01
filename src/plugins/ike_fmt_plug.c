/*
 * PSK cracker patch for JtR. Hacked together during March of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com> .
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under GPL
 *
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2007 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * psk-crack.c -- IKE Aggressive Mode Pre-Shared Key cracker for ike-scan
 *
 * Author: Roy Hills
 * Date: 8 July 2004
 *
 * July, 2012, JimF small changes made, many more should be done.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_ike;
#elif FMT_REGISTERS_H
john_register_one(&fmt_ike);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "ike-crack.h"

#define FORMAT_LABEL            "IKE"
#define FORMAT_NAME             "PSK"
#define FORMAT_TAG              "$ike$*"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME          "HMAC MD5/SHA1 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        32
#define BINARY_SIZE             20 /* SHA1 */
#define BINARY_SIZE_SMALLER     16 /* MD5 */
#define SALT_SIZE               sizeof(psk_entry)
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_ALIGN              sizeof(size_t)
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      64

#ifndef OMP_SCALE
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests ike_tests[] = {
	{"$ike$*0*5c7916ddf8db4d233b3b36005bb3ccc115a73807e11a897be943fd4a2d0f942624cb00588d8b3a0a26502b73e639df217ef6c4cb90f96b0a3c3ef2f62ed025b4a705df9de65e33e380c1ba5fa23bf1f9911bbf388d0844256fa0131fc5cf8acb396936ba3295b4637b039d93f58db90a3a1cf1ef5051103bacf6e1a3334f9f89*fde8c68c5f324c7dbcbadde1d757af6962c63496c009f77cad647f2997fd4295e50821453a6dc2f6279fd7fef68768584d9cee0da6e68a534a097ce206bf77ecc798310206f3f82d92d02c885794e0a430ceb2d6b43c2aff45a6e14c6558382df0692ff65c2724eef750764ee456f31424a5ebd9e115d826bbb9722111aa4e01*b2a3c7aa4be95e85*756e3fa11c1b102c*00000001000000010000002c01010001000000240101000080010001800200018003000180040002800b0001000c000400007080*01000000ac100202*251d7ace920b17cb34f9d561bca46d037b337d19*e045819a64edbf022620bff3efdb935216584cc4*b9c594fa3fca6bb30a85c4208a8df348", "abc123"},
	{"$ike$*0*9bdee7aa341cf1a6c19bc0191106b5056537ce6b837cd70678ea5a3ccb606b56dee4548feb67f24fd6f4d5f58967a9ff3c674d9d79e4195b7def5aac147c9fe9abdc2f8ba2eca58f4c863fedc7a8c8e1ad6e1551b1e44bf9a0e258561a5db1c2ca1e8b5dfda1b012012b6fdf24ecd07da6b10d76ab3b58d07b30b4f9da26aee4*c9b7ef0610a22b3e1c88b1a01ce4d4110edf6baa122ed1285eb2184cd75d30a11520a725c2d263de5a157f77f953880732f3b14521836d7f3585cb0ce3fcadf81c541dde2680bd81953cf88e8f8096c173470694ca7414fff9df0cdcdbb9d4f70ef1d6347293b507cfad965e2d2c1fa07326353e9a493d93284970040344fb11*3506592130312567*6c362583ce7a2a26*00000001000000010000002c01010001000000240101000080010001800200028003000180040002800b0001000c000400007080*01000000ac100202*84943233f42a0b5a9b33c327162fe0efee2545e4*76f451dce3fea6402b67f3fddae561ebdb4a6efe*f63f237b3c0f1fe57a5b852203cfd27cbf0c78d4", "abc123"},
	{NULL}
};

static psk_entry *cur_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	crypt_out = mem_calloc(sizeof(*crypt_out), self->params.max_keys_per_crypt);
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ptr, *ctcopy, *keeptr;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;	/* skip leading '$ike$*' */
	if (*ctcopy != '0' && *ctcopy != '1')
		goto error;
	/* skip '*0' */
	ctcopy += 1;
	if (*ctcopy != '*')
		goto error;
	ctcopy += 1;
	if (!(ptr = strtokm(ctcopy, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) > MAXLEN)
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*")))
		goto error;
	if (strlen(ptr) != 32 && strlen(ptr) != 40) // md5 or sha1 length.
		goto error;
	if (!ishexlc(ptr))
		goto error;

	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static psk_entry cs;

	cs.isnortel = atoi(&ciphertext[FORMAT_TAG_LEN]);
	load_psk_params(&ciphertext[FORMAT_TAG_LEN+2], NULL, &cs);

	return (void *)&cs;
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

	p = strrchr(ciphertext, '*') + 1;
	for (i = 0; i < BINARY_SIZE_SMALLER; i++) {
		out[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void set_salt(void *salt)
{
	cur_salt = (psk_entry *)salt;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		compute_hash(cur_salt, saved_key[index], (unsigned char*)crypt_out[index]);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*((uint32_t*)binary) == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (*((uint32_t*)binary) == crypt_out[index][0]);
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_SMALLER);
}

static void ike_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

/*
 * For ike, the hash algorithm used for hmac
 * is returned as the first "tunable cost":
 * 1: MD5
 * 2: SHA1
 *
 * However, the there is almost no difference in speed,
 * so if the different hash types for HMAC shouldn't be reported,
 * just define IKE_REPORT_TUNABLE_COSTS to be 0 instead of 1.
 */
#define IKE_REPORT_TUNABLE_COSTS	1

#if IKE_REPORT_TUNABLE_COSTS
static unsigned int tunable_cost_hmac_hash_type(void *salt)
{
	psk_entry *my_salt = salt;

	return (unsigned int) my_salt->hash_type;
}
#endif
struct fmt_main fmt_ike = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE_SMALLER,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
		{
#if IKE_REPORT_TUNABLE_COSTS
			"hash algorithm used for hmac [1:MD5 2:SHA1]",
#else
			NULL
#endif
		},
		{ FORMAT_TAG },
		ike_tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
#if IKE_REPORT_TUNABLE_COSTS
			tunable_cost_hmac_hash_type,
#else
			NULL
#endif
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		ike_set_key,
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

#endif /* plugin stanza */
