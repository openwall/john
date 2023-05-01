/*
 * This software was written by JimF jfoug AT cox dot net
 * in 2016. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2016 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_o3logon;
#elif FMT_REGISTERS_H
john_register_one(&fmt_o3logon);
#else

#include <string.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "unicode.h"
#include "base64_convert.h"


#define FORMAT_LABEL                    "o3logon"
#define FORMAT_NAME                     "Oracle O3LOGON protocol"
#define FORMAT_TAG                      "$o3logon$"
#define FORMAT_TAG_LEN                  (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME                  "SHA1 DES 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                7

#define PLAINTEXT_LENGTH                32

#define BINARY_SIZE                     0
#define BINARY_ALIGN                    1
#define MAX_USERNAME_LEN                30
#define SALT_SIZE                       (sizeof(ora9_salt))
#define SALT_ALIGN                      (sizeof(unsigned int))
#define CIPHERTEXT_LENGTH               16
#define MAX_HASH_LEN                    (FORMAT_TAG_LEN+MAX_USERNAME_LEN+1+32+1+80)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		64

#ifndef OMP_SCALE
#define OMP_SCALE               128 // MKPC and scale tuned for i7
#endif


//#define DEBUG_ORACLE
//
//  The keys are $ora9i$  user  $  auth_sess_key $ auth_pass_key     These can be found in sniffed network traffic.
static struct fmt_tests tests[] = {
	{"$o3logon$PASSWORD9$8CF28B36E4F3D2095729CF59510003BF$3078D7DE44385654CC952A9C56E2659B", "password9"},
	{"$o3logon$scott$819D062FE5D93F79FF19BDAFE2F9872A$C6D1ED7E6F4D3A6D94F1E49460122D39A3832CC792AD7137", "scottscottscott1"},
	{"$o3logon$SCOTT$8E9E3E07864D99BB602C443F45E4AFC1$3591851B327BB85A114BD73D51B80AF58E942002B9612F82", "scottscottscott1234"},
	{"$o3logon$scott$4488AFD7905E9966912CA680A3C0A23E$628FBAC5CF0E5548743E16123BF027B9314D7EE8B4E30DB213F683F8D7E786EA", "scottscottscott12345"},
	{NULL}
};


typedef struct ora9_salt_t {
	int userlen, auth_pass_len;
	UTF16 user[MAX_USERNAME_LEN+1];
	unsigned char auth_sesskey[16];
	unsigned char auth_pass[40];
} ora9_salt;

static ora9_salt *cur_salt;

static UTF16 (*cur_key)[PLAINTEXT_LENGTH + 1];
static char (*plain_key)[PLAINTEXT_LENGTH + 1];
static int *cur_key_len;
static int *cracked, any_cracked;

static DES_key_schedule desschedule1;	// key 0x0123456789abcdef

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	DES_set_key_unchecked((DES_cblock *)"\x01\x23\x45\x67\x89\xab\xcd\xef", &desschedule1);
	cur_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cur_key));
	plain_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*plain_key));
	cur_key_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*cur_key_len));
	cracked = mem_calloc(self->params.max_keys_per_crypt,
	                     sizeof(*cracked));
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(cur_key_len);
	MEM_FREE(plain_key);
	MEM_FREE(cur_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *cp;
	char tmp[32*5+1];
	UTF16 cur_key_mixedcase[MAX_USERNAME_LEN+2];
	int len, extra;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ciphertext += FORMAT_TAG_LEN;
	cp = strchr(ciphertext, '$');
	if (!cp)
		return 0;

	// make sure username fits in MAX_USERNAME_LEN UTF16
	if (cp-ciphertext > sizeof(tmp)-1)
		return 0;
	memcpy(tmp, ciphertext, cp-ciphertext);
	tmp[cp-ciphertext] = 0;
	len = enc_to_utf16((UTF16 *)cur_key_mixedcase, MAX_USERNAME_LEN+1, (unsigned char*)tmp, strlen(tmp));
	if (len < 0 || (len == 0 && cp-ciphertext)) {
		static int error_shown = 0;
#ifdef HAVE_FUZZ
		if (options.flags & (FLG_FUZZ_CHK | FLG_FUZZ_DUMP_CHK))
			return 0;
#endif
		if (!error_shown)
			fprintf(stderr, "%s: Input file is not UTF-8. Please use --input-enc to specify a codepage.\n", self->params.label);
		error_shown = 1;
		return 0;
	}
	if (len > MAX_USERNAME_LEN)
		return 0;

	ciphertext = cp+1;
	cp = strchr(ciphertext, '$');
	if (!cp || cp-ciphertext != 32 || hexlenu(ciphertext, 0) != 32)
		return 0;
	ciphertext = cp+1;
	cp = strchr(ciphertext, '$');
	len = strlen(ciphertext);
	if (!len || len > 40*2 || cp || len%16 || hexlenu(ciphertext, &extra) != len || extra)
		return 0;
	return 1;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[MAX_HASH_LEN*5+1];
	strnzcpy(out, ciphertext, MAX_HASH_LEN+1);
	enc_strupper(&out[FORMAT_TAG_LEN]);
	return out;
}

static void set_salt(void *salt) {
	cur_salt = (ora9_salt *)salt;
}

static void oracle_set_key(char *key, int index) {
	UTF16 cur_key_mixedcase[PLAINTEXT_LENGTH+1];
	UTF16 *c;
	int key_length;

	strnzcpy(plain_key[index], key, sizeof(*plain_key));
	// Can't use enc_to_utf16_be() because we need to do utf16_uc later
	key_length = enc_to_utf16(cur_key_mixedcase, PLAINTEXT_LENGTH, (unsigned char*)key, strlen(key));

	if (key_length < 0)
		key_length = strlen16(cur_key_mixedcase);

	// We convert and uppercase in one shot
	key_length = utf16_uc(cur_key[index], PLAINTEXT_LENGTH, cur_key_mixedcase, key_length);
	// we have no way to 'undo' here, since the expansion is due to single-2-multi expansion in the upcase,
	// and we can not 'fix' our password.  We simply have to 'not' properly decrypt this one, but protect ourselves.
	if (key_length < 0)
		key_length *= -1;
	cur_key_len[index] = key_length * sizeof(UTF16);
	// Now byte-swap to UTF16-BE
	c = cur_key[index];
	while((*c = *c << 8 | *c >> 8))
		c++;

#ifdef DEBUG_ORACLE
	dump_stuff_msg("cur_key    ", (unsigned char*)cur_key[index], cur_key_len[index]);
#endif
}

static char *get_key(int index) {
	return plain_key[index];
}

static int ORACLE_TNS_Create_Key_SHA1 (unsigned char *input, int input_len, const unsigned char *Entropy, int EntropyLen, int desired_keylen, unsigned char *out_key)
{
	SHA_CTX ctx;

	SHA1_Init (&ctx);
	SHA1_Update (&ctx, input, input_len);
	SHA1_Update (&ctx, Entropy, EntropyLen);
	SHA1_Final (out_key, &ctx);

	SHA1_Init (&ctx);
	SHA1_Update (&ctx, input, input_len);
	SHA1_Update (&ctx, "\x2", 1);
	SHA1_Update (&ctx, &out_key[1], 19);
	SHA1_Update (&ctx, Entropy, EntropyLen);
	SHA1_Final (out_key+20, &ctx);
	return 0;
}

static int ORACLE_TNS_Decrypt_3DES_CBC (unsigned char* input, int input_len, const unsigned char key[24], unsigned char *decrypted)
{
	DES_key_schedule ks1,ks2,ks3;
	unsigned char iv[] = {0x80,0x20,0x40,0x04,0x08,0x02,0x10,0x01};

	DES_set_key_unchecked((DES_cblock*) &key[0], &ks1);
	DES_set_key_unchecked((DES_cblock*) &key[8], &ks2);
	DES_set_key_unchecked((DES_cblock*) &key[16], &ks3);

	DES_ede3_cbc_encrypt(input,decrypted,input_len,&ks1,&ks2,&ks3,(DES_cblock*) iv,DES_DECRYPT);

	return 0;
}

static unsigned char fixed31 [] = {0xA2,0xFB,0xE6,0xAD,0x4C,0x7D,0x1E,0x3D,
                                   0x6E,0xB0,0xB7,0x6C,0x97,0xEF,0xFF,0x84,
                                   0x44,0x71,0x02,0x84,0xAC,0xF1,0x3B,0x29,
                                   0x5C,0x0F,0x0C,0xB1,0x87,0x75,0xEF};
static unsigned char fixed23 [] = {0xF2,0xFF,0x97,0x87,0x15,0x37,0x07,0x76,
                                   0x07,0x27,0xE2,0x7F,0xA3,0xB1,0xD6,0x73,
                                   0x3F,0x2F,0xD1,0x52,0xAB,0xAC,0xC0};

static int ORACLE_TNS_Decrypt_Password_9i (unsigned char OracleHash[8], unsigned char *auth_sesskey, int auto_sesskeylen, unsigned char *auth_password, int auth_passwordlen, unsigned char *decrypted)
{
	unsigned char triple_des_key[64];
	unsigned char sesskey[16];
	unsigned char obfuscated[256];
	int PassLen = auth_passwordlen;

	ORACLE_TNS_Create_Key_SHA1 (OracleHash, 8, fixed31, sizeof(fixed31), 24, triple_des_key);
	ORACLE_TNS_Decrypt_3DES_CBC (auth_sesskey, 16, triple_des_key, sesskey);
	ORACLE_TNS_Create_Key_SHA1 (sesskey, 16, fixed23, sizeof(fixed23), 24, triple_des_key);
	ORACLE_TNS_Decrypt_3DES_CBC (auth_password, PassLen, triple_des_key, obfuscated);

	//ORACLE_TNS_DeObfuscate (triple_des_key, obfuscated, &PassLen);
	memcpy(decrypted, &obfuscated[PassLen-4], 4);
	memcpy(&decrypted[4], &obfuscated[4], PassLen-4);

	return PassLen;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int idx = 0;
	if (any_cracked) {
		memset(cracked, 0, sizeof(*cracked) * count);
		any_cracked = 0;
	}

#ifdef DEBUG_ORACLE
		dump_stuff_msg("cur_salt    ", buf,  cur_salt->userlen+key_length);
#endif

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (idx = 0; idx < count; idx++) {
		unsigned char buf[256], buf1[256];
		unsigned int l;
		uint32_t iv[2];
		DES_key_schedule desschedule2;

		l = cur_salt->userlen + cur_key_len[idx];
		memcpy(buf, cur_salt->user, cur_salt->userlen);
		memcpy(buf + cur_salt->userlen, cur_key[idx], cur_key_len[idx]);

		iv[0] = iv[1] = 0;
		DES_ncbc_encrypt((unsigned char *)buf, buf1, l, &desschedule1, (DES_cblock *) iv, DES_ENCRYPT);
		DES_set_key_unchecked((DES_cblock *)iv, &desschedule2);
		iv[0] = iv[1] = 0;
		DES_ncbc_encrypt((unsigned char *)buf, buf1, l, &desschedule2, (DES_cblock *) iv, DES_ENCRYPT);

#ifdef DEBUG_ORACLE
		dump_stuff_msg("  iv (the hash key) ", (unsigned char*)&iv[0], 8);
#endif

		ORACLE_TNS_Decrypt_Password_9i ((unsigned char*)iv, cur_salt->auth_sesskey, 16, cur_salt->auth_pass, cur_salt->auth_pass_len, buf);
		if (!strncmp((char*)buf, plain_key[idx], strlen(plain_key[idx])))
		{
			cracked[idx] = 1;
#ifdef _OPENMP
#pragma omp atomic
#endif
			any_cracked |= 1;
		}
	}
	return count;
}

static void *get_salt(char *ciphertext)
{
	static ora9_salt salt;
	UTF8 tmp[MAX_USERNAME_LEN*5+1];
	char *cp;

	memset(&salt, 0, sizeof(salt));
	ciphertext += FORMAT_TAG_LEN;
	cp = strchr(ciphertext, '$');
	strncpy((char*)tmp, ciphertext, cp-ciphertext);
	tmp[cp-ciphertext] = 0;
	salt.userlen = enc_to_utf16_be(salt.user, MAX_USERNAME_LEN, tmp, cp-ciphertext);
	if (salt.userlen < 0)
		salt.userlen = strlen16(salt.user);
	salt.userlen *= 2;
	base64_convert(cp+1,e_b64_hex,32,salt.auth_sesskey,e_b64_raw,16,0,0);
	cp = strchr(cp+1, '$') + 1;
	salt.auth_pass_len = strlen(cp)/2;
	base64_convert(cp,e_b64_hex,salt.auth_pass_len*2,salt.auth_pass,e_b64_raw,salt.auth_pass_len,0,0);
	return &salt;
}

// Public domain hash function by DJ Bernstein (salt is a username)
static int salt_hash(void *salt)
{
	UTF16 *s = ((UTF16*)salt) + 1;
	unsigned int hash = 5381;

	while (*s)
		hash = ((hash << 5) + hash) ^ *s++;

	return hash & (SALT_HASH_SIZE - 1);
}

static int cmp_all(void *binary, int count)
{
	return any_cracked;
}

static int cmp_one(void *binary, int count)
{
	return cracked[count];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_o3logon = {
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
		FMT_8_BIT | FMT_UNICODE | FMT_ENC | FMT_SPLIT_UNIFIES_CASE | FMT_CASE | FMT_OMP,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		salt_hash,
		NULL,
		set_salt,
		oracle_set_key,
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
#endif /* HAVE_LIBCRYPTO */
