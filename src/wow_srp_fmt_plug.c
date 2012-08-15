/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2012, JimF  jfoug at cox.net
 *
 * This implements the SRP protocol, with blizzard documented specifics
 *
 *
 * U = username in upper case
 * P = password in upper case
 * s = random salt value.
 *
 * x = SHA1(s, H(U, ":", P));   
 * v = 47^x % 112624315653284427036559548610503669920632123929604336254260115573677366691719
 *
 * v is the 'verifier' value (256 bit value).  
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
#define MAX_KEYS_PER_CRYPT		1

// salt is in hex  (salt and salt2)
static struct fmt_tests tests[] = {
	{WOWSIG"6D00CD214C8473C7F4E9DC77AE8FC6B3944298C48C7454E6BB8296952DCFE78D$73616C74", "PASSWORD", {"SOLAR"}},
	{WOWSIG"A35DCC134159A34F1D411DA7F38AB064B617D5DBDD9258FE2F23D5AB1CF3F685$73616C7432", "PASSWORD2", {"DIZ"}},
	{WOWSIG"A35DCC134159A34F1D411DA7F38AB064B617D5DBDD9258FE2F23D5AB1CF3F685$73616C7432*DIZ", "PASSWORD2"},
	{NULL}
};

#ifdef HAVE_GMP
static mpz_t z_mod, z_base, z_exp, z_rop;
#else
static BIGNUM *z_mod, *z_base, *z_exp, *z_rop;
BN_CTX *BN_ctx;
#endif

static unsigned char saved_salt[SALT_SIZE];
static unsigned char user_id[SALT_SIZE];
static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static SHA_CTX ctx;
static ARCH_WORD_32 crypt_out[8]; // 256 bits, which is size of 47^x % 112624315653284427036559548610503669920632123929604336254260115573677366691719

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

static void init(struct fmt_main *self)
{
#ifdef HAVE_GMP
	mpz_init_set_str(z_mod, "112624315653284427036559548610503669920632123929604336254260115573677366691719", 10);
	mpz_init_set_str(z_base, "47", 10);
	mpz_init_set_str(z_exp, "1", 10);
	mpz_init(z_rop);
	// Now, properly initialzed mpz_exp, so it is 'large enough' to hold any SHA1 value 
	// we need to put into it. Then we simply need to copy in the data, and possibly set
	// the limb count size.
	mpz_mul_2exp(z_exp, z_exp, 159);
#else
	z_mod=BN_new();
	BN_dec2bn(&z_mod, "112624315653284427036559548610503669920632123929604336254260115573677366691719");
	z_base=BN_new();
	BN_set_word(z_base, 47);
	z_exp=BN_new();
	z_rop=BN_new();
	BN_ctx = BN_CTX_new();
#endif
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
static int get_hash_0(int index)       { return crypt_out[0] & 0xF; }
static int get_hash_1(int index)       { return crypt_out[0] & 0xFF; }
static int get_hash_2(int index)       { return crypt_out[0] & 0xFFF; }
static int get_hash_3(int index)       { return crypt_out[0] & 0xFFFF; }
static int get_hash_4(int index)       { return crypt_out[0] & 0xFFFFF; }
static int get_hash_5(int index)       { return crypt_out[0] & 0xFFFFFF; }
static int get_hash_6(int index)       { return crypt_out[0] & 0x7FFFFFF; }

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
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);

	strupr(saved_key);
}

static char *get_key(int index)
{
	saved_key[saved_key_length] = 0;
	return saved_key;
}

// x = SHA1(s, H(U, ":", P));   
// v = 47^x % 112624315653284427036559548610503669920632123929604336254260115573677366691719

static void crypt_all(int count)
{
	unsigned char Tmp[20], HashStr[80], *p;
	int i;
//	int skips;
//	ARCH_WORD_32 *p1, *p2;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, user_id, strlen((char*)user_id));
	SHA1_Update(&ctx, ":", 1);
	SHA1_Update(&ctx, saved_key, saved_key_length);
	SHA1_Final(Tmp, &ctx);
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, saved_salt, strlen((char*)saved_salt));
	SHA1_Update(&ctx, Tmp, 20);
	SHA1_Final(Tmp, &ctx);
	// Ok, now Tmp is v

#ifdef HAVE_GMP
#if 1
	// Speed, 17194/s
	p = HashStr;
	for (i = 0; i < 20; ++i) {
		*p++ = itoa16[Tmp[i]>>4];
		*p++ = itoa16[Tmp[i]&0xF];
	}
	*p = 0;

	mpz_set_str(z_exp, (char*)HashStr, 16);
	mpz_powm (z_rop, z_base, z_exp, z_mod );
	mpz_get_str ((char*)HashStr, 16, z_rop);

	p = HashStr;

	for (i = 0; i < FULL_BINARY_SIZE; i++) {
		((unsigned char*)crypt_out)[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#else
	// Speed, 17445/s


	// This code works for 32 bit (on LE intel systems).  I may need to 'fix' it for 64 bit.
	// GMP is BE format of a huge 'flat' integer. Thus, we need to put into
	// BE format (each word), and then put the words themselves, into BE order.
//	memcpy(z_exp->_mp_d, Tmp, 20);
	p1 = (ARCH_WORD_32*)Tmp;
	p2 = (ARCH_WORD_32*)z_exp->_mp_d;
	// NOTE z_exp was allocated 'properly' with 2^160 bit size.
	if (!p1[0]) {
		z_exp->_mp_size = 4;
		p2[3] = JOHNSWAP(p1[1]);
		p2[2] = JOHNSWAP(p1[2]);
		p2[1] = JOHNSWAP(p1[3]);
		p2[0] = JOHNSWAP(p1[4]);
	} else {
		z_exp->_mp_size = 5;
		p2[4] = JOHNSWAP(p1[0]);
		p2[3] = JOHNSWAP(p1[1]);
		p2[2] = JOHNSWAP(p1[2]);
		p2[1] = JOHNSWAP(p1[3]);
		p2[0] = JOHNSWAP(p1[4]);
	}

	mpz_powm (z_rop, z_base, z_exp, z_mod );

//	memcpy(crypt_out, z_rop->_mp_d, 32);
	p1 = (ARCH_WORD_32*)z_rop->_mp_d;
	p2 = (ARCH_WORD_32*)crypt_out;
	p2[7] = JOHNSWAP(p1[0]);
	p2[6] = JOHNSWAP(p1[1]);
	p2[5] = JOHNSWAP(p1[2]);
	p2[4] = JOHNSWAP(p1[3]);
	p2[3] = JOHNSWAP(p1[4]);
	p2[2] = JOHNSWAP(p1[5]);
	p2[1] = JOHNSWAP(p1[6]);
	p2[0] = JOHNSWAP(p1[7]);
#endif
#else
	// using oSSL's BN to do expmod.
	z_exp = BN_bin2bn(Tmp,20,z_exp);
	BN_mod_exp(z_rop, z_base, z_exp, z_mod, BN_ctx);
	BN_bn2bin(z_rop, (unsigned char*)crypt_out);
#endif

}

static int cmp_all(void *binary, int count)
{
	return *((ARCH_WORD_32*)binary) == *((ARCH_WORD_32*)crypt_out);
}
static int cmp_one(void *binary, int count)
{
	return *((ARCH_WORD_32*)binary) == *((ARCH_WORD_32*)crypt_out);
}

static int cmp_exact(char *source, int index)
{
	void *binary = get_binary(source);
	return !memcmp(binary, crypt_out, BINARY_SIZE);
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
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
