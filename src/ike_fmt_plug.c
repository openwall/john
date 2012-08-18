/* PSK cracker patch for JtR. Hacked together during March of 2012 by
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

#include <string.h>
#include <assert.h>
#include <errno.h>
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "ike-crack.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               16
static int omp_t = 1;
#endif

#define FORMAT_LABEL		"ike"
#define FORMAT_NAME		"IKE PSK HMAC-MD5 / HMAC-SHA1"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1
#define PLAINTEXT_LENGTH	32
#define BINARY_SIZE		20 /* SHA1 */
#define BINARY_SIZE_SMALLER	16 /* MD5 */
#define SALT_SIZE		sizeof(psk_entry)
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	16

static struct fmt_tests ike_tests[] = {
	{"$ike$*0*5c7916ddf8db4d233b3b36005bb3ccc115a73807e11a897be943fd4a2d0f942624cb00588d8b3a0a26502b73e639df217ef6c4cb90f96b0a3c3ef2f62ed025b4a705df9de65e33e380c1ba5fa23bf1f9911bbf388d0844256fa0131fc5cf8acb396936ba3295b4637b039d93f58db90a3a1cf1ef5051103bacf6e1a3334f9f89*fde8c68c5f324c7dbcbadde1d757af6962c63496c009f77cad647f2997fd4295e50821453a6dc2f6279fd7fef68768584d9cee0da6e68a534a097ce206bf77ecc798310206f3f82d92d02c885794e0a430ceb2d6b43c2aff45a6e14c6558382df0692ff65c2724eef750764ee456f31424a5ebd9e115d826bbb9722111aa4e01*b2a3c7aa4be95e85*756e3fa11c1b102c*00000001000000010000002c01010001000000240101000080010001800200018003000180040002800b0001000c000400007080*01000000ac100202*251d7ace920b17cb34f9d561bca46d037b337d19*e045819a64edbf022620bff3efdb935216584cc4*b9c594fa3fca6bb30a85c4208a8df348", "abc123"},
	{"$ike$*0*9bdee7aa341cf1a6c19bc0191106b5056537ce6b837cd70678ea5a3ccb606b56dee4548feb67f24fd6f4d5f58967a9ff3c674d9d79e4195b7def5aac147c9fe9abdc2f8ba2eca58f4c863fedc7a8c8e1ad6e1551b1e44bf9a0e258561a5db1c2ca1e8b5dfda1b012012b6fdf24ecd07da6b10d76ab3b58d07b30b4f9da26aee4*c9b7ef0610a22b3e1c88b1a01ce4d4110edf6baa122ed1285eb2184cd75d30a11520a725c2d263de5a157f77f953880732f3b14521836d7f3585cb0ce3fcadf81c541dde2680bd81953cf88e8f8096c173470694ca7414fff9df0cdcdbb9d4f70ef1d6347293b507cfad965e2d2c1fa07326353e9a493d93284970040344fb11*3506592130312567*6c362583ce7a2a26*00000001000000010000002c01010001000000240101000080010001800200028003000180040002800b0001000c000400007080*01000000ac100202*84943233f42a0b5a9b33c327162fe0efee2545e4*76f451dce3fea6402b67f3fddae561ebdb4a6efe*f63f237b3c0f1fe57a5b852203cfd27cbf0c78d4", "abc123"},
	{NULL}
};

static psk_entry *cur_salt;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$ike$", 5);
}

static void *get_salt(char *ciphertext)
{
	static psk_entry cs;
	cs.isnortel = atoi(&ciphertext[6]);
	load_psk_params(&ciphertext[8], NULL, &cs);
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

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }

static void set_salt(void *salt)
{
	cur_salt = (psk_entry *)salt;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++)
	{
		compute_hash(cur_salt, saved_key[index], (unsigned char*)crypt_out[index]);
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
	for (; index < count; index++)
		if (*((ARCH_WORD_32*)binary) == crypt_out[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return (*((ARCH_WORD_32*)binary) == crypt_out[index][0]);
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	return !memcmp(binary, crypt_out[index], BINARY_SIZE_SMALLER);
}

static void ike_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > 8)
		saved_key_length = 8;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main ike_fmt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		ike_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		set_salt,
		ike_set_key,
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
