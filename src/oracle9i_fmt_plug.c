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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_oracle9i;
#elif FMT_REGISTERS_H
john_register_one(&fmt_oracle9i);
#else

#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "unicode.h"
#include "base64_convert.h"
#include "memdbg.h"

#define FORMAT_LABEL                    "oracle9i"
#define FORMAT_NAME                     "Oracle 9i (sniffed)"
#define FORMAT_TAG                      "$ora9i$"
#define FORMAT_TAG_LEN                  (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME                  "DES 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                -1

#define PLAINTEXT_LENGTH                32

#define BINARY_SIZE                     0
#define BINARY_ALIGN                    1
#define MAX_USERNAME_LEN                30
#define SALT_SIZE                       (sizeof(ora9_salt))
#define SALT_ALIGN                      (sizeof(unsigned int))
#define CIPHERTEXT_LENGTH               16

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1


//#define DEBUG_ORACLE
//
//  The keys are $ora9i$  user  $  auth_sess_key $ auth_pass_key     These can be found in sniffed network traffic.
static struct fmt_tests tests[] = {
	{"$ora9i$PASSWORD9$8CF28B36E4F3D2095729CF59510003BF$3078D7DE44385654CC952A9C56E2659B", "password9"},
	{"$ora9i$scott$819D062FE5D93F79FF19BDAFE2F9872A$C6D1ED7E6F4D3A6D94F1E49460122D39A3832CC792AD7137", "scottscottscott1"},
	{"$ora9i$SCOTT$8E9E3E07864D99BB602C443F45E4AFC1$3591851B327BB85A114BD73D51B80AF58E942002B9612F82", "scottscottscott1234"},
	{"$ora9i$scott$4488AFD7905E9966912CA680A3C0A23E$628FBAC5CF0E5548743E16123BF027B9314D7EE8B4E30DB213F683F8D7E786EA", "scottscottscott12345"},
	{"4488AFD7905E9966912CA680A3C0A23E$628FBAC5CF0E5548743E16123BF027B9314D7EE8B4E30DB213F683F8D7E786EA", "scottscottscott12345",      {"scott"} },
	{NULL}
};

typedef struct ora9_salt_t {
	unsigned int userlen, auth_pass_len;
	UTF16 user[MAX_USERNAME_LEN+1];
	unsigned char auth_sesskey[16];
	unsigned char auth_pass[40];
} ora9_salt;

static ora9_salt *cur_salt;
static UTF16 cur_key[PLAINTEXT_LENGTH + 1];

static DES_key_schedule desschedule1;	// key 0x0123456789abcdef


static int key_length;
static char *plain_key;
static int cracked;

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *cp;
	char tmp[32*5+1];
	UTF16 cur_key_mixedcase[MAX_USERNAME_LEN+2];
	int len;

	if (strlen(ciphertext) < FORMAT_TAG_LEN)
		return 0;
	if (memcmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;
	ciphertext += FORMAT_TAG_LEN;
	cp = strchr(ciphertext, '$');
	if (!cp)
		return 0;

	// make sure username fits in MAX_USERNAME_LEN UTF16
	memcpy(tmp, ciphertext, cp-ciphertext);
	tmp[cp-ciphertext] = 0;
	len = enc_to_utf16((UTF16 *)cur_key_mixedcase, MAX_USERNAME_LEN+1, (unsigned char*)tmp, strlen(tmp));
	if (len < 0 || len > MAX_USERNAME_LEN)
		return 0;

	ciphertext = cp+1;
	cp = strchr(ciphertext, '$');
	if (!cp || cp-ciphertext != 32 || hexlenu(ciphertext) != 32)
		return 0;
	ciphertext = cp+1;
	cp = strchr(ciphertext, '$');
	if (cp || strlen(ciphertext)%16 || hexlenu(ciphertext) != strlen(ciphertext))
		return 0;
	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	static char cp[512];

	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN))
		return split_fields[1];
	if (!split_fields[0])
		return split_fields[1];
	sprintf (cp, "%s%s$%s", FORMAT_TAG, split_fields[0], split_fields[1]);
	return cp;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[512];
	strnzcpy(out, ciphertext, sizeof(out));
	enc_strupper(&out[FORMAT_TAG_LEN]);
	return out;
}

static void init(struct fmt_main *self)
{
	unsigned char deskey[8];

	deskey[0] = 0x01;
	deskey[1] = 0x23;
	deskey[2] = 0x45;
	deskey[3] = 0x67;
	deskey[4] = 0x89;
	deskey[5] = 0xab;
	deskey[6] = 0xcd;
	deskey[7] = 0xef;

	DES_set_key((DES_cblock *)deskey, &desschedule1);
}

static void set_salt(void *salt) {
	cur_salt = (ora9_salt *)salt;
}

static void oracle_set_key(char *key, int index) {
	UTF16 cur_key_mixedcase[PLAINTEXT_LENGTH+1];
	UTF16 *c;

	plain_key = key;
	// Can't use enc_to_utf16_be() because we need to do utf16_uc later
	key_length = enc_to_utf16((UTF16 *)cur_key_mixedcase, PLAINTEXT_LENGTH, (unsigned char*)key, strlen(key));

	if (key_length < 0)
		key_length = strlen16(cur_key_mixedcase);

	// We convert and uppercase in one shot
	key_length = utf16_uc((UTF16 *)cur_key, PLAINTEXT_LENGTH, cur_key_mixedcase, key_length);
	// we have no way to 'undo' here, since the expansion is due to single-2-multi expansion in the upcase,
	// and we can not 'fix' our password.  We simply have to 'not' properly decrypt this one, but protect ourselves.
	if (key_length < 0)
		key_length *= -1;

	// Now byte-swap to UTF16-BE
	c = cur_key;
	while((*c = *c << 8 | *c >> 8))
		c++;
	key_length *= sizeof(UTF16);

#ifdef DEBUG_ORACLE
	dump_stuff_msg("cur_key    ", (unsigned char*)&cur_key[0], key_length);
#endif
}

static char *get_key(int index) {
	return plain_key;
}

int ORACLE_TNS_Create_Key_SHA1 (unsigned char* input, int input_len, const unsigned char* Entropy, int EntropyLen, int desired_keylen, unsigned char* out_key)
{
	const unsigned char fixed23 [] = {0xF2,0xFF,0x97,0x87,0x15,0x37,0x07,0x76,0x07,0x27,0xE2,0x7F,0xA3,0xB1,0xD6,0x73,0x3F,0x2F,0xD1,0x52,0xAB,0xAC,0xC0};
	unsigned char sha_hash[20];
	unsigned char sha_hash2[20];
	SHA_CTX ctx;
	int i;

	if (Entropy == NULL)
	{
		Entropy = fixed23;
		EntropyLen = 23;
	}

	for (i = 0; i < desired_keylen; i += 20)
	{
		SHA1_Init (&ctx);
		SHA1_Update (&ctx, input, input_len);
		if (i != 0)
		{
			sha_hash2[0]=2;
			SHA1_Update (&ctx, sha_hash2, i);
		}
		SHA1_Update (&ctx, Entropy, EntropyLen);
		SHA1_Final (sha_hash, &ctx);

		memcpy (sha_hash2, sha_hash, 20);
		if (desired_keylen-i < 20)
			memcpy (out_key+i, sha_hash, desired_keylen-i);
		else
			memcpy (out_key+i, sha_hash, 20);
	}

	return 0;

}

int ORACLE_TNS_Decrypt_3DES_CBC (unsigned char* input, int input_len, const unsigned char key[24], unsigned char* decrypted)
{
	DES_key_schedule ks1,ks2,ks3;
	const unsigned char iv[] = {0x80,0x20,0x40,0x04,0x08,0x02,0x10,0x01};

	DES_set_key((DES_cblock*) &key[0], &ks1);
	DES_set_key((DES_cblock*) &key[8], &ks2);
	DES_set_key((DES_cblock*) &key[16], &ks3);

	DES_ede3_cbc_encrypt(input,decrypted,input_len,&ks1,&ks2,&ks3,(DES_cblock*) iv,DES_DECRYPT);

	return 0;
}


static int ORACLE_TNS_Decrypt_Password_9i (unsigned char OracleHash[8], unsigned char* auth_sesskey, int auto_sesskeylen, unsigned char *auth_password, int auth_passwordlen, unsigned char* decrypted)
{
	const unsigned char fixed31 [] = {0xA2,0xFB,0xE6,0xAD,0x4C,0x7D,0x1E,0x3D,0x6E,0xB0,0xB7,0x6C,0x97,0xEF,0xFF,0x84,0x44,0x71,0x02,0x84,0xAC,0xF1,0x3B,0x29,0x5C,0x0F,0x0C,0xB1,0x87,0x75,0xEF};
	unsigned char triple_des_key[64];
	unsigned char sesskey[16];
	unsigned char obfuscated[256];
	int PassLen = auth_passwordlen;

	ORACLE_TNS_Create_Key_SHA1 (OracleHash, 8, fixed31, sizeof(fixed31), 24, triple_des_key);
	ORACLE_TNS_Decrypt_3DES_CBC (auth_sesskey, 16, triple_des_key, sesskey);
	ORACLE_TNS_Create_Key_SHA1 (sesskey, 16, NULL, 0, 40, triple_des_key);
	ORACLE_TNS_Decrypt_3DES_CBC (auth_password, PassLen, triple_des_key, obfuscated);

	//ORACLE_TNS_DeObfuscate (triple_des_key, obfuscated, &PassLen);
	memcpy(decrypted, &obfuscated[PassLen-4], 4);
	memcpy(&decrypted[4], &obfuscated[4], PassLen-4);

	return PassLen;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	unsigned char buf[256], buf1[256];
	unsigned int l;
	ARCH_WORD_32 iv[2];
	DES_key_schedule desschedule2;

	cracked = 0;
	l = cur_salt->userlen + key_length;
	memcpy(buf, cur_salt->user, cur_salt->userlen);
	memcpy(buf + cur_salt->userlen, cur_key, key_length);

#ifdef DEBUG_ORACLE
	dump_stuff_msg("cur_salt    ", buf,  cur_salt->userlen+key_length);
#endif

	iv[0] = iv[1] = 0;
	DES_ncbc_encrypt((unsigned char *)buf, buf1, l, &desschedule1, (DES_cblock *) iv, DES_ENCRYPT);
	DES_set_key((DES_cblock *)iv, &desschedule2);
	iv[0] = iv[1] = 0;
	DES_ncbc_encrypt((unsigned char *)buf, buf1, l, &desschedule2, (DES_cblock *) iv, DES_ENCRYPT);

#ifdef DEBUG_ORACLE
	dump_stuff_msg("  iv (the hash key) ", (unsigned char*)&iv[0], 8);
#endif

	ORACLE_TNS_Decrypt_Password_9i ((unsigned char*)iv, cur_salt->auth_sesskey, 16, cur_salt->auth_pass, cur_salt->auth_pass_len, buf);
	if (!strncmp((char*)buf, plain_key, strlen(plain_key)))
		cracked = 1;

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
	return cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_oracle9i = {
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
		FMT_8_BIT | FMT_UNICODE | FMT_UTF8 | FMT_SPLIT_UNIFIES_CASE | FMT_CASE,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		prepare,
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
		cmp_all,
		cmp_exact
	}
};

#endif /* plugin stanza */
