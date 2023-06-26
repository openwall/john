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
 * This is oracle O10g-logon format. NOTE, if the hashes came from a
 * Oracle 10g, and the hash data can be sniffed from network traffic
 * TNS records.
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_o10glogon;
#elif FMT_REGISTERS_H
john_register_one(&fmt_o10glogon);
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
#include "aes.h"
#include "md5.h"
#include "unicode.h"
#include "base64_convert.h"

#define FORMAT_LABEL                    "o10glogon"
#define FORMAT_NAME                     "Oracle 10g-logon protocol"
#define FORMAT_TAG                      "$o10glogon$"
#define FORMAT_TAG_LEN                  (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME                  "DES-AES128-MD5 32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT               ""
#define BENCHMARK_LENGTH                7

#define PLAINTEXT_LENGTH                32

#define BINARY_SIZE                     0
#define BINARY_ALIGN                    1
#define MAX_USERNAME_LEN                30
#define SALT_SIZE                       (sizeof(ora10g_salt))
#define SALT_ALIGN                      (sizeof(unsigned int))
#define CIPHERTEXT_LENGTH               16
#define MAX_HASH_LEN                    (FORMAT_TAG_LEN+MAX_USERNAME_LEN+1+64+1+64+1+160)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		16

#ifndef OMP_SCALE
#define OMP_SCALE               8 // Tuned w/ MKPC for core i7
#endif

//#define DEBUG_ORACLE
//
//  The keys are $o10glogon$oracle-user-name$auth_sess_key$auth_sess_key_c$auth_password
//  These can be found in sniffed network traffic.
static struct fmt_tests tests[] = {
	{"$o10glogon$jimf$6DA8BE6D9713B7F9190DC0F87F1BB1BDFFE44EB1892E40915592980ECCE60AA3$1C08586339E5806DD45CF8E6D83CC6EA2B8CDCDE7CC9F00ADF43DA0F07309090$E2F3D778138213BF01FD743F2092FC976FD60AB2C9F4A1B1D9B08439325421B1", "JimF"},
	{"$o10glogon$SESA218390$3B16F14C3DC6048C993000E2BF543BAB489DF7BD8D6061B7274CC9E1DB743E08$1695D5255EDF15CA6B1F14C5CB39C72C98E2CC2B62FB3224ECA5A6A6790511D4$F0F64E384E567F44E9DF8D7F4C029AA59770FA75094F1C26A66C45AFA9913987", "jimf"},
	{"$o10glogon$TESTUSER$EEABE812530C6D4432F781DFC14A7C7F81EAE1804F340D3289732477FD351FCC$7B244D7A1DB5ABE553FB9B7325110024911FCBE95EF99E7965A754BC41CF31C0$4C5E28E66B6382117F9D41B08957A3B9E363B42760C33B44CA5D53EA90204ABE", "TESTPASS"},
	{NULL}
};

typedef struct ora10g_salt_t {
	int userlen, auth_pass_len;
	UTF16 user[MAX_USERNAME_LEN+1];
	unsigned char auth_sesskey[32];
	unsigned char auth_sesskey_c[32];
	unsigned char auth_pass[80];
} ora10g_salt;

static ora10g_salt *cur_salt;

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
	if (!cp || cp-ciphertext != 64 || hexlenu(ciphertext, 0) != 64)
		return 0;
	ciphertext = cp+1;
	cp = strchr(ciphertext, '$');
	if (!cp || cp-ciphertext != 64 || hexlenu(ciphertext, 0) != 64)
		return 0;
	ciphertext = cp+1;
	len = strlen(ciphertext);
	cp = strchr(ciphertext, '$');
	if (!len || len > 80*2 || cp || len%16 || hexlenu(ciphertext, &extra) != len || extra)
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
	cur_salt = (ora10g_salt *)salt;
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

static void ORACLE_TNS_Decrypt_AES128_CBC (unsigned char aes_key_bytes[16], unsigned char* input, int input_len, unsigned char* output)
{
	unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	AES_KEY key;
	AES_set_decrypt_key(aes_key_bytes, 128, &key);
	AES_cbc_encrypt(input, output, input_len, &key, iv, AES_DECRYPT);
}

static int terminate_ascii_string (char* ascii_string_not_terminated, int len)
{
	int ascii_len = 0;
	unsigned char padding_byte;
	int pos;

	for (pos=0; ; pos++) {
		if ((ascii_string_not_terminated[pos] < 32) |
		    (ascii_string_not_terminated[pos] > 126))
		    break;
	}

	ascii_len = pos;
	padding_byte = ascii_string_not_terminated[pos];

	for (;pos<len; pos++) {
		if (ascii_string_not_terminated[pos] != padding_byte)
			return -1;
	}

	ascii_string_not_terminated[ascii_len] = 0;
	return ascii_len;
}
static void ORACLE_TNS_Combine_SessKeys (unsigned char server_sesskey[16], unsigned char client_sesskey[16], unsigned char* output)
{
	unsigned char combined_sesskeys[16];
	int i;
	MD5_CTX ctx;

	for (i=0;i<16;i++)
		combined_sesskeys[i] = server_sesskey[i] ^ client_sesskey[i];
	MD5_Init (&ctx);
	MD5_Update (&ctx, combined_sesskeys,16);
	MD5_Final (output, &ctx);
}


static int ORACLE_TNS_Decrypt_Password_10g (unsigned char OracleHash[8], unsigned char *auth_sesskey, unsigned char *auth_sesskey_c, unsigned char *auth_password, int auth_passwordlen, unsigned char *decrypted)
{
	int passlen = 0;
	unsigned char aes_key_bytes[32];
	unsigned char decrypted_server_sesskey[32];
	unsigned char decrypted_client_sesskey[32];
	unsigned char combined_sesskeys[16];
	char decrypted_password[64];

	memset (aes_key_bytes,0,sizeof(aes_key_bytes));
	memcpy (aes_key_bytes,OracleHash,8);

	// Decrypt server and client session keys
	ORACLE_TNS_Decrypt_AES128_CBC (aes_key_bytes, auth_sesskey, 32, decrypted_server_sesskey);
	ORACLE_TNS_Decrypt_AES128_CBC (aes_key_bytes, auth_sesskey_c, 32, decrypted_client_sesskey);

	// Combine server and client session keys
	ORACLE_TNS_Combine_SessKeys (&decrypted_server_sesskey[16], &decrypted_client_sesskey[16], combined_sesskeys);

	// Decrypt auth password with combined session key
	ORACLE_TNS_Decrypt_AES128_CBC (combined_sesskeys, auth_password, auth_passwordlen, (unsigned char*) decrypted_password);

	// terminate decrypted password with NULL
	passlen = terminate_ascii_string (&decrypted_password[16], auth_passwordlen-16);
	if (passlen != -1)
		strncpy ((char*)decrypted, &decrypted_password[16], passlen);

	return passlen;
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

		ORACLE_TNS_Decrypt_Password_10g ((unsigned char*)iv, cur_salt->auth_sesskey, cur_salt->auth_sesskey_c, cur_salt->auth_pass, cur_salt->auth_pass_len, buf);
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
	static ora10g_salt salt;
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
	base64_convert(cp+1,e_b64_hex,64,salt.auth_sesskey,e_b64_raw,32,0,0);
	cp = strchr(cp+1, '$');
	base64_convert(cp+1,e_b64_hex,64,salt.auth_sesskey_c,e_b64_raw,32,0,0);
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

struct fmt_main fmt_o10glogon = {
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
