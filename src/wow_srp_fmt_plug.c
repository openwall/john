/*
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
 *
 * This implements the SRP protocol, with Blizzard's (battlenet) documented
 * implementation specifics.
 *
 * U = username in upper case
 * P = password in upper case
 * s = random salt value.
 *
 * x = SHA1(s . SHA1(U . ":" . P));   
 * v = 47^x % 112624315653284427036559548610503669920632123929604336254260115573677366691719
 *
 * v is the 'verifier' value (256 bit value).  
 *
 * Added OMP.  Added 'default' oSSL BigNum exponentiation.
 * GMP exponentation (faster) is optional, and controled with HAVE_GMP in Makefile
 */

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


#define FORMAT_LABEL			"wowsrp"
#define FORMAT_NAME				"WoW (Battlenet) SRP sha1"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR EXP_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define WOWSIG					"$WoWSRP$"
#define WOWSIGLEN				8
// min plaintext len is 8  PW's are only alpha-num uppercase
#define PLAINTEXT_LENGTH		16
#define CIPHERTEXT_LENGTH		64

#define BINARY_SIZE				4
#define FULL_BINARY_SIZE		32
#define SALT_SIZE				(64+3)
#define USERNAMELEN             32

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		4

// salt is in hex  (salt and salt2)
static struct fmt_tests tests[] = {
	{WOWSIG"6D00CD214C8473C7F4E9DC77AE8FC6B3944298C48C7454E6BB8296952DCFE78D$73616C74", "PASSWORD", {"SOLAR"}},
	{WOWSIG"A35DCC134159A34F1D411DA7F38AB064B617D5DBDD9258FE2F23D5AB1CF3F685$73616C7432", "PASSWORD2", {"DIZ"}},
	{WOWSIG"A35DCC134159A34F1D411DA7F38AB064B617D5DBDD9258FE2F23D5AB1CF3F685$73616C7432*DIZ", "PASSWORD2"},
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
static unsigned char saved_salt[SALT_SIZE];
static unsigned char user_id[SALT_SIZE];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[8];


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
			self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	pSRP_CTX = mem_calloc_tiny(sizeof(*pSRP_CTX) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	for (i = 0; i < self->params.max_keys_per_crypt; ++i) {
#ifdef HAVE_GMP
		mpz_init_set_str(pSRP_CTX[i].z_mod, "112624315653284427036559548610503669920632123929604336254260115573677366691719", 10);
		mpz_init_set_str(pSRP_CTX[i].z_base, "47", 10);
		mpz_init_set_str(pSRP_CTX[i].z_exp, "1", 10);
		mpz_init(pSRP_CTX[i].z_rop);
		// Now, properly initialzed mpz_exp, so it is 'large enough' to hold any SHA1 value 
		// we need to put into it. Then we simply need to copy in the data, and possibly set
		// the limb count size.
		mpz_mul_2exp(pSRP_CTX[i].z_exp, pSRP_CTX[i].z_exp, 159);
#else
		pSRP_CTX[i].z_mod=BN_new();
		BN_dec2bn(&pSRP_CTX[i].z_mod, "112624315653284427036559548610503669920632123929604336254260115573677366691719");
		pSRP_CTX[i].z_base=BN_new();
		BN_set_word(pSRP_CTX[i].z_base, 47);
		pSRP_CTX[i].z_exp=BN_new();
		pSRP_CTX[i].z_rop=BN_new();
		pSRP_CTX[i].BN_ctx = BN_CTX_new();
#endif
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p, *q;

	if (strncmp(ciphertext, WOWSIG, WOWSIGLEN))
		return 0;

	q = p = &ciphertext[WOWSIGLEN];
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	if (q-p != CIPHERTEXT_LENGTH) 
		return 0;
	if (*q != '$') return 0;
	++q;
	p = strchr(q, '*');
	if (!p) return 0;
	if ( ((p-q)&1)) return 0;
	while (atoi16[ARCH_INDEX(*q)] != 0x7F)
		q++;
	if (q != p) return 0;
	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *pFmt) {
	// if user name not there, then add it
	static char ct[128+32+1];
	char *cp;

	if (!split_fields[1][0] || strncmp(split_fields[1], WOWSIG, WOWSIGLEN))  return split_fields[1];
	cp = strchr(split_fields[1], '*');
	if (cp) return split_fields[1];
	strnzcpy(ct, split_fields[1], 128);
	cp = &ct[strlen(ct)];
	*cp++ = '*';
	strnzcpy(cp, split_fields[0], USERNAMELEN);
	// upcase user name
	while (*cp) {
		if (*cp >= 'a' && *cp <= 'z')
			*cp -= 0x20;
		++cp;
	}
	return ct;
}

#if FMT_MAIN_VERSION > 9
static char *split(char *ciphertext, int index, struct fmt_main *pFmt) {
#else
static char *split(char *ciphertext, int index) {
#endif
	static char ct[128+32+1];
	char *cp;

	strnzcpy(ct, ciphertext, 128+32+1);
	cp = strchr(ct, '*');
	if (cp) *cp = 0;
	strupr(&ct[WOWSIGLEN]);
	if (cp) *cp = '*';
	return ct;
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

	p = &ciphertext[WOWSIGLEN];
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
	static unsigned long out_[SALT_SIZE/sizeof(unsigned long)+1];
	unsigned char *out = (unsigned char*)out_;
	char *p;
	int length=0;

	memset(out, 0, SALT_SIZE);
	p = &ciphertext[WOWSIGLEN+64+1];

	while (*p != '*') {
		out[++length] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	++p;
	out[0] = length;
	memcpy(out + length+1, p, strlen(p)+1);

	return out;
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
	unsigned char *cp = (unsigned char*)salt;
	memcpy(saved_salt, &cp[1], *cp);
	saved_salt[*cp] = 0;
	strcpy((char*)user_id, (char*)&cp[*cp+1]);
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH+1);
	strupr(saved_key[index]);
}

static char *get_key(int index)
{
	return saved_key[index];
}

// x = SHA1(s, H(U, ":", P));   
// v = 47^x % 112624315653284427036559548610503669920632123929604336254260115573677366691719

static void crypt_all(int count)
{
	int j;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (j = 0; j < count; ++j) {
		SHA_CTX ctx;
		unsigned char Tmp[20];

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, user_id, strlen((char*)user_id));
		SHA1_Update(&ctx, ":", 1);
		SHA1_Update(&ctx, saved_key[j], strlen(saved_key[j]));
		SHA1_Final(Tmp, &ctx);
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, saved_salt, strlen((char*)saved_salt));
		SHA1_Update(&ctx, Tmp, 20);
		SHA1_Final(Tmp, &ctx);
		// Ok, now Tmp is v

#ifdef HAVE_GMP
#if 1
		// Speed, 17194/s
	{
		unsigned char HashStr[80], *p;
		int i;
		p = HashStr;
		for (i = 0; i < 20; ++i) {
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
		pSRP_CTX[j].z_exp = BN_bin2bn(Tmp,20,pSRP_CTX[j].z_exp);
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

struct fmt_main fmt_blizzard = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
		tests
	}, {
		init,
		prepare,
		valid,
		split,
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
