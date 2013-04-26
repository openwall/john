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

#include <string.h>
#include "sha2.h"
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#ifdef HAVE_GMP
#include "gmp.h"
#define EXP_STR " GMP-exp"
#else
#include <openssl/bn.h>
#define EXP_STR " oSSL-exp"
#endif
#include "johnswap.h"
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE               64
#endif


#define FORMAT_LABEL			"clipperz"
#define FORMAT_NAME				"Clipperz SRP SHA256"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR EXP_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define CLIPPERZSIG					"$clipperz$"
#define CLIPPERZSIGLEN				10
#define PLAINTEXT_LENGTH		16
#define CIPHERTEXT_LENGTH		64

#define BINARY_SIZE				32
#define FULL_BINARY_SIZE		32
#define SALT_SIZE		sizeof(struct custom_salt)
#define USERNAMELEN             32

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		4

#define SZ 				128

// salt is in hex  (salt and salt2)
static struct fmt_tests tests[] = {
	{CLIPPERZSIG"e8be8c8d9c1d5dc79ecc7b15d1787d5b5dc22e815ddb0b37f6145ca667421f1f$e0bc11ee4db80a3ecabd293f5201cb747856361192c68f4133ea707c7d4d2d32*hackme@mailinator.com", "openwall"},
	{NULL}
};

#ifdef HAVE_GMP
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
static ARCH_WORD_32 (*crypt_out)[8];


static struct custom_salt {
	unsigned char saved_salt[SZ];
	unsigned char user_id[SZ];
} *cur_salt;

static void init(struct fmt_main *self)
{
	int i;
#if defined (_OPENMP)
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
			self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	pSRP_CTX = mem_calloc_tiny(sizeof(*pSRP_CTX) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
#ifdef HAVE_GMP
		mpz_init_set_str(pSRP_CTX[i].z_mod, "125617018995153554710546479714086468244499594888726646874671447258204721048803", 10);
		mpz_init_set_str(pSRP_CTX[i].z_base, "2", 10);
		mpz_init_set_str(pSRP_CTX[i].z_exp, "1", 10);
		mpz_init(pSRP_CTX[i].z_rop);
		// Now, properly initialzed mpz_exp, so it is 'large enough' to hold any SHA256 value
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

static int ishex(char *q)
{
       while (atoi16[ARCH_INDEX(*q)] != 0x7F)
               q++;
       return !*q;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy;
	char *keeptr;
	char *p = NULL;
	if (strncmp(ciphertext, CLIPPERZSIG, CLIPPERZSIGLEN))
		return 0;
	ctcopy = strdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += CLIPPERZSIGLEN;
	if ((p = strtok(ctcopy, "$")) == NULL)
		goto err;
	if (strlen(p) != CIPHERTEXT_LENGTH)
		goto err;
	if (!ishex(p))
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)
		goto err;
	if (strlen(p) > SZ)
		goto err;
	if ((p = strtok(NULL, "*")) == NULL)
		goto err;
	if (strlen(p) > SZ)
		goto err;
	if ((p = strtok(NULL, "*")))
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[FULL_BINARY_SIZE];
		ARCH_WORD dummy[1];
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	p = &ciphertext[CLIPPERZSIGLEN];
	for (i = 0; i < FULL_BINARY_SIZE; i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *salt(char *ciphertext)
{
	char *p;
	char *q;
	static struct custom_salt cs;
	p = ciphertext;
	p += (10 + 64 + 1);
	q = strrchr(ciphertext, '*');
	strncpy((char*)cs.saved_salt, p, q - p);
	p = strrchr(ciphertext, '*') + 1;
	strcpy((char*)cs.user_id, p);
	return (void *)&cs;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7FFFFFF; }
static int get_hash_0(int index)       { return crypt_out[index][0] & 0xF; }
static int get_hash_1(int index)       { return crypt_out[index][0] & 0xFF; }
static int get_hash_2(int index)       { return crypt_out[index][0] & 0xFFF; }
static int get_hash_3(int index)       { return crypt_out[index][0] & 0xFFFF; }
static int get_hash_4(int index)       { return crypt_out[index][0] & 0xFFFFF; }
static int get_hash_5(int index)       { return crypt_out[index][0] & 0xFFFFFF; }
static int get_hash_6(int index)       { return crypt_out[index][0] & 0x7FFFFFF; }

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

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
	int i;
	for (i = 0; i < len; ++i) {
		out[0] = itoa16[str[i]>>4];
		out[1] = itoa16[str[i]&0xF];
		out += 2;
	}
}

static void crypt_all(int count)
{
	int j;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (j = 0; j < count; ++j) {
		SHA256_CTX ctx;
		unsigned char Tmp[32];
		unsigned char TmpHex[64];

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

#ifdef HAVE_GMP
#if 1
		// Speed, 17194/s
	{
		unsigned char HashStr[80], *p;
		int i;
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

		for (i = 0; i < FULL_BINARY_SIZE; i++) {
			((unsigned char*)(crypt_out[j]))[i] =
				(atoi16[ARCH_INDEX(*p)] << 4) |
				atoi16[ARCH_INDEX(p[1])];
			p += 2;
		}
	}
#else
		// Speed, 17445/s
	{
		ARCH_WORD_32 *p1, *p2;

		// This code works for 32 bit (on LE intel systems).  I may need to 'fix' it for 64 bit.
		// GMP is BE format of a huge 'flat' integer. Thus, we need to put into
		// BE format (each word), and then put the words themselves, into BE order.
	//	memcpy(z_exp->_mp_d, Tmp, 20);
		p1 = (ARCH_WORD_32*)Tmp;
		p2 = (ARCH_WORD_32*)pSRP_CTX[j].z_exp->_mp_d;
		// NOTE z_exp was allocated 'properly' with 2^160 bit size.
		if (!p1[0]) {
			pSRP_CTX[j].z_exp->_mp_size = 4;
			p2[3] = JOHNSWAP(p1[1]);
			p2[2] = JOHNSWAP(p1[2]);
			p2[1] = JOHNSWAP(p1[3]);
			p2[0] = JOHNSWAP(p1[4]);
		} else {
			pSRP_CTX[j].z_exp->_mp_size = 5;
			p2[4] = JOHNSWAP(p1[0]);
			p2[3] = JOHNSWAP(p1[1]);
			p2[2] = JOHNSWAP(p1[2]);
			p2[1] = JOHNSWAP(p1[3]);
			p2[0] = JOHNSWAP(p1[4]);
		}

		mpz_powm (pSRP_CTX[j].z_rop, pSRP_CTX[j].z_base, pSRP_CTX[j].z_exp, pSRP_CTX[j].z_mod );

	//	memcpy(crypt_out[j], pSRP_CTX[j].z_rop->_mp_d, 32);
		p1 = (ARCH_WORD_32*)pSRP_CTX[j].z_rop->_mp_d;
		p2 = (ARCH_WORD_32*)(crypt_out[j]);
		p2[7] = JOHNSWAP(p1[0]);
		p2[6] = JOHNSWAP(p1[1]);
		p2[5] = JOHNSWAP(p1[2]);
		p2[4] = JOHNSWAP(p1[3]);
		p2[3] = JOHNSWAP(p1[4]);
		p2[2] = JOHNSWAP(p1[5]);
		p2[1] = JOHNSWAP(p1[6]);
		p2[0] = JOHNSWAP(p1[7]);
	}
#endif
#else
		// using oSSL's BN to do expmod.
		pSRP_CTX[j].z_exp = BN_bin2bn(Tmp,32,pSRP_CTX[j].z_exp);
		BN_mod_exp(pSRP_CTX[j].z_rop, pSRP_CTX[j].z_base, pSRP_CTX[j].z_exp, pSRP_CTX[j].z_mod, pSRP_CTX[j].BN_ctx);
		BN_bn2bin(pSRP_CTX[j].z_rop, (unsigned char*)(crypt_out[j]));
#endif
	}
}

static int cmp_all(void *binary, int count)
{
	int i;
	for (i = 0; i < count; ++i) {
		if (*((ARCH_WORD_32*)binary) == *((ARCH_WORD_32*)(crypt_out[i])))
			return 1;
	}
	return 0;
}
static int cmp_one(void *binary, int index)
{
	return *((ARCH_WORD_32*)binary) == *((ARCH_WORD_32*)(crypt_out[index]));
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
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		set_salt,
		set_key,
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
