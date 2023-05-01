/* This software was repurposed by Dhiru Kholia (dhiru at openwall.com)
 * in 2012.
 *
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2012. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2012 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Format was busted, just like wow-srp. It ONLY was handling binary residue
 * if the residue was exactly 64 hex bytes long. Well for exponentation, it
 * does not have to be 64 bytes. It can be shorter. We also handle case where
 * a shorter result number is 0 Lpadded to an even 64 bytes. split() should
 * be added to canonize these hashes, since they are same hash with
 * multiple representations.
 *
 * This implements the SRP protocol, with Clipperz documented
 * implementation specifics.
 *
 * s = random salt value.
 *
 * v is the 'verifier' value (256 bit value).
 *
 * Clipperz's offline database has following relevant fields,
 *
 * <script>_clipperz_dump_data_ = {  ...
 *
 * '2f2134e38b23534adfcd43c2f7223caf3a53a8db7ce800f1e918e8e0d06b8b7a': {
 * 	s: 'e0bc11ee4db80a3ecabd293f5201cb747856361192c68f4133ea707c7d4d2d32',
 * 	v: 'e8be8c8d9c1d5dc79ecc7b15d1787d5b5dc22e815ddb0b37f6145ca667421f1f
 * 	version: '0.2',
 * 	...
 * }
 * P algorithm:
 * h1 = hashlib.sha256(password + username).digest()
 * P = h2 = hashlib.sha256(h1).hexdigest()
 *
 * x algorithm:
 * x1 =  hashlib.sha256(s + P).digest()
 * x = hashlib.sha256(x1).hexdigest()
 *
 * v algorithm:
 * v = Clipperz.Crypto.SRP.g().powerModule(new Clipperz.Crypto.BigInt(x,16),Clipperz.Crypto.SRP.n());
 * n = 125617018995153554710546479714086468244499594888726646874671447258204721048803
 * g = 2 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBGMP || HAVE_LIBCRYPTO /* we need one of these for bignum */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_clipperz;
#elif FMT_REGISTERS_H
john_register_one(&fmt_clipperz);
#else

#include <string.h>
#ifdef HAVE_LIBGMP
#if HAVE_GMP_GMP_H
#include <gmp/gmp.h>
#else
#include <gmp.h>
#endif
#define EXP_STR " GMP-exp"
#else
#include <openssl/bn.h>
#define EXP_STR " oSSL-exp"
#endif

#ifdef _OPENMP
#include <omp.h>
#endif

#include "sha2.h"
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"

#define FORMAT_LABEL		"Clipperz"
#define FORMAT_NAME		"SRP"
#define ALGORITHM_NAME		"SHA256 32/" ARCH_BITS_STR EXP_STR

#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0x107

#define CLIPPERZSIG		"$clipperz$"
#define CLIPPERZSIGLEN		(sizeof(CLIPPERZSIG)-1)
#define PLAINTEXT_LENGTH	16
#define CIPHERTEXT_LENGTH	65

#define BINARY_SIZE		33
#define BINARY_ALIGN		4
#define FULL_BINARY_SIZE	33
#define SALT_SIZE		sizeof(struct custom_salt)
#define SALT_ALIGN		1
#define USERNAMELEN             32

#ifndef OMP_SCALE
#define OMP_SCALE               256 // MKPC & scale tuned for i7
#endif

#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	2

#define SZ 				128

// salt is in hex  (salt and salt2)
static struct fmt_tests tests[] = {
	{CLIPPERZSIG"e8be8c8d9c1d5dc79ecc7b15d1787d5b5dc22e815ddb0b37f6145ca667421f1f$e0bc11ee4db80a3ecabd293f5201cb747856361192c68f4133ea707c7d4d2d32*hackme@mailinator.com", "openwall"},
	{"$clipperz$05b18d6976d6cefad7c0c330c0c8a32ed69f19a8d68a94c3916c5ad1ba5ce37e5$RoljkWQajmS8OXFbsnqmZFTeB2How6hkoDd5QKu0DjthET3NmjTmOLumZe84nb7o*1", "password"},
	{"$clipperz$5b18d6976d6cefad7c0c330c0c8a32ed69f19a8d68a94c3916c5ad1ba5ce37e5$RoljkWQajmS8OXFbsnqmZFTeB2How6hkoDd5QKu0DjthET3NmjTmOLumZe84nb7o*1", "password"},
	{NULL}
};

#ifdef HAVE_LIBGMP
typedef struct t_SRP_CTX {
	mpz_t z_mod, z_base, z_exp, z_rop;
} SRP_CTX;
#else
typedef struct t_SRP_CTX {
	BIGNUM *z_mod, *z_base, *z_exp, *z_rop;
	BN_CTX *BN_ctx;
}SRP_CTX;
#endif

static SRP_CTX *pSRP_CTX;
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
// BN_bn2bin sometimes tries to write 33 bytes, hence allow some padding!
// that is because these are mod 0x115B8B692E0E045692CF280B436735C77A5A9E8A9E7ED56C965F87DB5B2A2ECE3
// which is a 65 hex digit number (33 bytes long).
static uint32_t (*crypt_out)[(FULL_BINARY_SIZE/4) + 1];

static struct custom_salt {
	unsigned char saved_salt[SZ];
	unsigned char user_id[SZ];
} *cur_salt;

static int max_keys_per_crypt;

static void init(struct fmt_main *self)
{
	int i;

	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc_align(sizeof(*saved_key),
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_align(sizeof(*crypt_out), self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	pSRP_CTX = mem_calloc_align(sizeof(*pSRP_CTX), self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	max_keys_per_crypt =  self->params.max_keys_per_crypt;

	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
#ifdef HAVE_LIBGMP
		mpz_init_set_str(pSRP_CTX[i].z_mod, "125617018995153554710546479714086468244499594888726646874671447258204721048803", 10);
		mpz_init_set_str(pSRP_CTX[i].z_base, "2", 10);
		mpz_init_set_str(pSRP_CTX[i].z_exp, "1", 10);
		mpz_init(pSRP_CTX[i].z_rop);
		// Now, properly initialized mpz_exp, so it is 'large enough' to hold any SHA256 value
		// we need to put into it. Then we simply need to copy in the data, and possibly set
		// the limb count size.
		mpz_mul_2exp(pSRP_CTX[i].z_exp, pSRP_CTX[i].z_exp, 159);
#else
		pSRP_CTX[i].z_mod=BN_new();
		BN_dec2bn(&pSRP_CTX[i].z_mod, "125617018995153554710546479714086468244499594888726646874671447258204721048803");
		pSRP_CTX[i].z_base=BN_new();
		BN_set_word(pSRP_CTX[i].z_base, 2);
		pSRP_CTX[i].z_exp=BN_new();
		pSRP_CTX[i].z_rop=BN_new();
		pSRP_CTX[i].BN_ctx = BN_CTX_new();
#endif
	}
}

void done(void)
{
	int i;
	for (i = 0; i < max_keys_per_crypt; ++i) {
#ifdef HAVE_LIBGMP
		mpz_clear(pSRP_CTX[i].z_mod);
		mpz_clear(pSRP_CTX[i].z_base);
		mpz_clear(pSRP_CTX[i].z_exp);
		mpz_clear(pSRP_CTX[i].z_rop);
#else
		BN_clear_free(pSRP_CTX[i].z_mod);
		BN_clear_free(pSRP_CTX[i].z_base);
		BN_clear_free(pSRP_CTX[i].z_exp);
		BN_clear_free(pSRP_CTX[i].z_rop);
		BN_CTX_free(pSRP_CTX[i].BN_ctx);
#endif
	}
	MEM_FREE(pSRP_CTX);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p = NULL;
	if (strncmp(ciphertext, CLIPPERZSIG, CLIPPERZSIGLEN))
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += CLIPPERZSIGLEN;
	if ((p = strtokm(ctcopy, "$")) == NULL)
		goto err;
	if (strlen(p) > CIPHERTEXT_LENGTH)
		goto err;
	if (!ishex_oddOK(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)
		goto err;
	if (strlen(p) > SZ-1)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)
		goto err;
	if (strlen(p) > SZ-1)
		goto err;
	if ((p = strtokm(NULL, "*")))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt) {
	static char ct[128+2*SZ+1];
	char *cp;

	if (strncmp(ciphertext, CLIPPERZSIG, CLIPPERZSIGLEN))
		return ciphertext;
	strnzcpy(ct, ciphertext, sizeof(ct));
	cp = strchr(&ct[CLIPPERZSIGLEN], '$');
	if (!cp)
		return ciphertext;
	*cp = 0;
	strlwr(&ct[CLIPPERZSIGLEN]);
	*cp = '$';
	if (ct[CLIPPERZSIGLEN] == '0') {
		char *cpi = &ct[CLIPPERZSIGLEN];
		char *cpo = cpi;
		while (*cpi == '0')
			++cpi;
		do {
			*cpo++ = *cpi;
		} while (*cpi++);
	}
	return ct;
}
static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[FULL_BINARY_SIZE];
		uint32_t dummy[1];
	} buf;
	unsigned char *out = buf.c;
	char *p, *q;
	int i;

	p = &ciphertext[CLIPPERZSIGLEN];
	q = strchr(p, '$');
	memset(buf.c, 0, sizeof(buf));
	while (*p == '0')
		++p;
	if ((q-p)&1) {
		out[0] = atoi16[ARCH_INDEX(*p)];
		++p;
	} else {
		out[0] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	for (i = 1; i < FULL_BINARY_SIZE; i++)  {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
		if (p >= q)
			break;
	}

	return out;
}

static void *get_salt(char *ciphertext)
{
	char *p;
	char *q;
	static struct custom_salt cs;
	memset(&cs, 0, sizeof(cs));
	p = ciphertext;
	p = strchr(&ciphertext[CLIPPERZSIGLEN], '$') + 1;
	q = strrchr(ciphertext, '*');
	strncpy((char*)cs.saved_salt, p, q - p);
	p = strrchr(ciphertext, '*') + 1;
	strcpy((char*)cs.user_id, p);
	return (void *)&cs;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	unsigned int hash = 0;
	char *p = (char *)salt;

	while (*p) {
		hash <<= 1;
		hash += (unsigned char)*p++;
		if (hash >> SALT_HASH_LOG) {
			hash ^= hash >> SALT_HASH_LOG;
			hash &= (SALT_HASH_SIZE - 1);
		}
	}

	hash ^= hash >> SALT_HASH_LOG;
	hash &= (SALT_HASH_SIZE - 1);

	return hash;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

inline static void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int j;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (j = 0; j < count; ++j) {
		SHA256_CTX ctx;
		unsigned char Tmp[32];
		unsigned char TmpHex[64];

		memset(crypt_out[j], 0, sizeof(crypt_out[j]));
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, saved_key[j], strlen(saved_key[j]));
		SHA256_Update(&ctx, cur_salt->user_id, strlen((char*)cur_salt->user_id));
		SHA256_Final(Tmp, &ctx);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, Tmp, 32);
		SHA256_Final(Tmp, &ctx);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, cur_salt->saved_salt, strlen((char*)cur_salt->saved_salt));
		hex_encode(Tmp, 32, TmpHex);
		SHA256_Update(&ctx, TmpHex, 64);
		SHA256_Final(Tmp, &ctx);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, Tmp, 32);
		SHA256_Final(Tmp, &ctx);

#ifdef HAVE_LIBGMP
	{
		unsigned char HashStr[80], *p;
		int i, todo;
		p = HashStr;
		for (i = 0; i < 32; ++i) {
			*p++ = itoa16[Tmp[i]>>4];
			*p++ = itoa16[Tmp[i]&0xF];
		}
		*p = 0;

		mpz_set_str(pSRP_CTX[j].z_exp, (char*)HashStr, 16);
		mpz_powm (pSRP_CTX[j].z_rop, pSRP_CTX[j].z_base, pSRP_CTX[j].z_exp, pSRP_CTX[j].z_mod );
		mpz_get_str ((char*)HashStr, 16, pSRP_CTX[j].z_rop);

		p = HashStr;
		todo = strlen((char*)p);
		if (todo&1) {
			((unsigned char*)(crypt_out[j]))[0] = atoi16[ARCH_INDEX(*p)];
			++p;
			--todo;
		} else {
			((unsigned char*)(crypt_out[j]))[0] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
			p += 2;
			todo -= 2;
		}
		todo >>= 1;
		for (i = 1; i <= todo; i++) {
			((unsigned char*)(crypt_out[j]))[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
			p += 2;
		}
	}
#else
		// using oSSL's BN to do expmod.
		pSRP_CTX[j].z_exp = BN_bin2bn(Tmp,32,pSRP_CTX[j].z_exp);
		BN_mod_exp(pSRP_CTX[j].z_rop, pSRP_CTX[j].z_base, pSRP_CTX[j].z_exp, pSRP_CTX[j].z_mod, pSRP_CTX[j].BN_ctx);
		BN_bn2bin(pSRP_CTX[j].z_rop, (unsigned char*)(crypt_out[j]));
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int i;
	for (i = 0; i < count; ++i) {
		if (*((uint32_t*)binary) == *((uint32_t*)(crypt_out[i])))
			return 1;
	}
	return 0;
}
static int cmp_one(void *binary, int index)
{
	return *((uint32_t*)binary) == *((uint32_t*)(crypt_out[index]));
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(get_binary(source), crypt_out[index], BINARY_SIZE);
}

struct fmt_main fmt_clipperz = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
		{ NULL },
		{ CLIPPERZSIG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		get_binary,
		get_salt,
		{ NULL },
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
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
#endif /* HAVE_LIBGMP || HAVE_LIBCRYPTO */
