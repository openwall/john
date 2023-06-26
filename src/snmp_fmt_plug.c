/*
 * Cracker for SNMPv3 USM hashes, https://tools.ietf.org/html/rfc3414.
 *
 * This software is Copyright (c) 2017, Dhiru Kholia <dhiru [at] openwall.com>,
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Thanks to https://www.0x0ff.info/2013/snmpv3-authentification/ for the very
 * clear explanation of the algorithms involved in SNMPv3 USM.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_snmp;
#elif FMT_REGISTERS_H
john_register_one(&fmt_snmp);
#else

#include <string.h>
#include <stdint.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define OMP_SCALE               2  // Tuned w/ MKPC for core i7

#include "formats.h"
#include "md5.h"
#include "hmacmd5.h"
#include "sha.h"
#include "hmac_sha.h"
#include "misc.h"
#include "common.h"
#include "params.h"
#include "options.h"

#define FORMAT_LABEL            "SNMP"
#define FORMAT_NAME             "SNMPv3 USM"
#define FORMAT_TAG              "$SNMPv3$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)
#define ALGORITHM_NAME          "HMAC-MD5-96/HMAC-SHA1-96 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             0
#define BINARY_ALIGN            1
#define SALT_SIZE               sizeof(struct custom_salt)
#define SALT_ALIGN              sizeof(uint32_t)
#define MAX_SALT_LEN            1500
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      4

static struct fmt_tests tests[] = {
	// https://wiki.wireshark.org/SampleCaptures, snmp_usm.pcap, pippo, md5
	{"$SNMPv3$1$3$3081b10201033011020430f6f3d5020300ffe304010702010304373035040d80001f888059dc486145a2632202010802020ab90405706970706f040c00000000000000000000000004080000000103d5321a0460826ecf6443956d4c364bfc6f6ffc8ee0df000ffd0955af12d2c0f3c60fadea417d2bb80c0b2c1fa7a46ce44f9f16e15ee830a49881f60ecfa757d2f04000eb39a94058121d88ca20eeef4e6bf06784c67c15f144915d9bc2c6a0461da92a4abe$80001f888059dc486145a26322$19395e67894fda182414849f", "pippoxxx"},
	// https://wiki.wireshark.org/SampleCaptures, snmp_usm.pcap, pippo, same as above but with missing algorithm specifier (0 instead of 1)
	{"$SNMPv3$0$3$3081b10201033011020430f6f3d5020300ffe304010702010304373035040d80001f888059dc486145a2632202010802020ab90405706970706f040c00000000000000000000000004080000000103d5321a0460826ecf6443956d4c364bfc6f6ffc8ee0df000ffd0955af12d2c0f3c60fadea417d2bb80c0b2c1fa7a46ce44f9f16e15ee830a49881f60ecfa757d2f04000eb39a94058121d88ca20eeef4e6bf06784c67c15f144915d9bc2c6a0461da92a4abe$80001f888059dc486145a26322$19395e67894fda182414849f", "pippoxxx"},
	// https://wiki.wireshark.org/SampleCaptures, snmp_usm.pcap, pippo3, sha1
	{"$SNMPv3$2$76$30820144020103301102043cdca370020300ffe304010302010304383036040d80001f888059dc486145a2632202010802020aba0406706970706f33040c0000000000000000000000000408f9a7cd5639adc7de0481f12d4e0febddef162199aa61bb97f44b84d975d9cef001d31eed660a193c22362c2ba6d203932822baa6c5d0032cc5cd7a8b7ac7b2fc005820ea72d72ffe59d3696be2bc8d5bdffb2de6fc775ed26cbf2d49a513704867665126775b8ffcaf3c07c19f9ecefb20293af7a6beecb6a5f2e3ba812ed9d71d21679007546f3acc6b72aff2baff2688451e74434dc9e6dab2f1b5e149691ced9fb4283fc8f85e3e7ebbe833353076fbdea7a11bc13a8c5ea62385b519e8bd2ab15f646572f487c8eb471eb0b069c5cc500eb8abc0227746d4ee8a5d9f0d6bfd9ece27f3f99ad5937c3e9be08e3074963796d3a13907fa1f17d213$80001f888059dc486145a26322$3de2a23a91ef278f8277b3f5", "pippoxxx"},
	// https://www.0x0ff.info/2013/snmpv3-authentification/
	{"$SNMPv3$1$0$30818002010330110204580b8cc7020300ffe30401050201030431302f041180001f888062dc7f4c15465c510000000002010302017c040475736572040c00000000000000000000000004003035041180001f888062dc7f4c15465c51000000000400a11e0204334304ff0201000201003010300e060a2b06010201041e0105010500$80001f888062dc7f4c15465c5100000000$9b1b71e33603a30c125f095d", "useruseruser"},
	// UTF-8 password
	{"$SNMPv3$1$4$3081a30201033011020416396d42020300ffe304010302010304393037041180001f88804883c95f7803fa580000000002010102016904046c756c75040c00000000000000000000000004080000000166c4ecb40450cee8d8c70a64bc0b508bb2a5625f9916a35a4c1f2d1a4d436c02312edad700a1a21bb23c319b073ed8b2a84d3829961e87af1a30daa443f7408dcc0dbee952b8fb0eab20760488908f31047b31caefba$80001f88804883c95f7803fa5800000000$9fa2a2e12cff0ca34794e988", "1234567£"},
	// SNMPv3 over IPv6
	{"$SNMPv3$0$4$3081a302010330110204551e91ab020300ffcf04010302010304393037041180001f88804883c95f7803fa580000000002010202015404046c756c75040c00000000000000000000000004080000000296c59db40450b0228ff64c7311310b1c41e63b999087495bb482700f40646ec63e461490ff985436cc8dfd63ed0bc1e66b307eab019bdb406e27df3c175eecbf82504639694efd38e4eff6bd91c524443a962fb331e8$80001f88804883c95f7803fa5800000000$af477d4cc2e0d31e9340acf9", "1234567£"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int *cracked, cracked_count;

static struct custom_salt {
	uint32_t authProtocol;
	unsigned char salt[MAX_SALT_LEN];
	uint32_t salt_length;
	unsigned char engineID[32]; // has to be in between 5 and 32 (both inclusive)
	uint32_t engineLength;
	unsigned char msgAuthenticationParameters[12];
} *cur_salt;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_key = mem_calloc(sizeof(*saved_key), self->params.max_keys_per_crypt);
	cracked = mem_calloc(sizeof(*cracked), self->params.max_keys_per_crypt);
	cracked_count = self->params.max_keys_per_crypt;
}

static void done(void)
{
	MEM_FREE(cracked);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	int value, extra;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;

	ctcopy += TAG_LENGTH;
	if ((p = strtokm(ctcopy, "$")) == NULL) // algorithm
		goto err;
	if (!isdec(p))
		goto err;
	value = atoi(p);
	if (value != 0 && value != 1 && value != 2)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // packet number, for debugging
		goto err;
	if (!isdec(p))
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // salt (wholeMsg)
		goto err;
	if (hexlenl(p, &extra) > MAX_SALT_LEN * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // msgAuthoritativeEngineID / snmpEngineID
		goto err;
	if (hexlenl(p, &extra) > 32 * 2 || extra)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) // msgAuthenticationParameters (hash)
		goto err;
	if (hexlenl(p, &extra) != 12 * 2 || extra)
		goto err;

	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static void *get_salt(char *ciphertext)
{
	static struct custom_salt cs;
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *p;
	int i;

	memset(&cs, 0, SALT_SIZE);
	ctcopy += TAG_LENGTH;
	p = strtokm(ctcopy, "$");
	cs.authProtocol = atoi(p);
	p = strtokm(NULL, "$");
	p = strtokm(NULL, "$");
	cs.salt_length = strlen(p) / 2;
	for (i = 0; i < cs.salt_length; i++)
		cs.salt[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "$");
	cs.engineLength = strlen(p) / 2;
	for (i = 0; i < cs.engineLength; i++)
		cs.engineID[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];
	p = strtokm(NULL, "$");
	for (i = 0; i < 12; i++)
		cs.msgAuthenticationParameters[i] = (atoi16[ARCH_INDEX(p[2 * i])] << 4) | atoi16[ARCH_INDEX(p[2 * i + 1])];

	MEM_FREE(keeptr);
	return &cs;
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;
}

/* Password to Key Sample Code for MD5, from RFC 3414 A.2.1 and Wireshark */
static void snmp_usm_password_to_key_md5(const uint8_t *password, uint32_t
		passwordlen, const uint8_t *engineID, uint32_t engineLength,
		uint8_t *key)
{
	uint8_t	*cp, password_buf[64];
	uint32_t password_index = 0;
	uint32_t count = 0, i;
	MD5_CTX ctx;

	MD5_Init(&ctx);
	/**********************************************/
	/* Use while loop until we've done 1 Megabyte */
	/**********************************************/
	while (count < 1048576) {
		cp = password_buf;
		if (passwordlen != 0) {
			for (i = 0; i < 64; i++) {
				/*************************************************/
				/* Take the next octet of the password, wrapping */
				/* to the beginning of the password as necessary.*/
				/*************************************************/
				*cp++ = password[password_index++];
				if (password_index >= passwordlen)
					password_index = 0;
			}
		} else {
			*cp = 0;
		}
		MD5_Update(&ctx, password_buf, 64);
		count += 64;
	}
	MD5_Final(key, &ctx);

	/*****************************************************/
	/* Now localize the key with the engineID and pass   */
	/* through MD5 to produce final key                  */
	/* May want to ensure that engineLength <= 32,       */
	/* otherwise need to use a buffer larger than 64     */
	/*****************************************************/
	memcpy(password_buf, key, 16);
	memcpy(password_buf+16, engineID, engineLength);
	memcpy(password_buf+16+engineLength, key, 16);

	MD5_Init(&ctx);
	MD5_Update(&ctx, password_buf, 32+engineLength);
	MD5_Final(key, &ctx);
}

/* Password to Key Sample Code for SHA, from RFC 3414 A.2.2 and Wireshark */
static void snmp_usm_password_to_key_sha(const uint8_t *password, uint32_t
		passwordlen, const uint8_t *engineID, uint32_t engineLength,
		uint8_t *key)
{
	uint8_t	*cp, password_buf[72];
	uint32_t password_index = 0;
	uint32_t count = 0, i;
	SHA_CTX ctx;

	SHA1_Init(&ctx);
	/**********************************************/
	/* Use while loop until we've done 1 Megabyte */
	/**********************************************/
	while (count < 1048576) {
		cp = password_buf;
		if (passwordlen != 0) {
			for (i = 0; i < 64; i++) {
				/*************************************************/
				/* Take the next octet of the password, wrapping */
				/* to the beginning of the password as necessary.*/
				/*************************************************/
				*cp++ = password[password_index++];
				if (password_index >= passwordlen)
					password_index = 0;
			}
		} else {
			*cp = 0;
		}
		SHA1_Update(&ctx, password_buf, 64);
		count += 64;
	}
	SHA1_Final(key, &ctx);

	/*****************************************************/
	/* Now localize the key with the engineID and pass   */
	/* through SHA to produce final key                  */
	/* May want to ensure that engineLength <= 32,       */
	/* otherwise need to use a buffer larger than 72     */
	/*****************************************************/
	memcpy(password_buf, key, 20);
	memcpy(password_buf+20, engineID, engineLength);
	memcpy(password_buf+20+engineLength, key, 20);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, password_buf, 40+engineLength);
	SHA1_Final(key, &ctx);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

	memset(cracked, 0, sizeof(cracked[0])*cracked_count);

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		HMACMD5Context ctx;
		unsigned char authKey[20];
		unsigned char out[20];

/*
 * Missed optimization potential:
 * This should be re-worked to cache authKey (in global malloc'ed arrays) for
 * the MD5 and SHA-1 variations of the algorithm if/as they're first computed
 * and then reuse them for further salts.
 */
		if (cur_salt->authProtocol == 1) {
			snmp_usm_password_to_key_md5((const uint8_t *)saved_key[index],
					strlen(saved_key[index]),
					cur_salt->engineID,
					cur_salt->engineLength, authKey);
			hmac_md5_init_rfc2104(authKey, 16, &ctx);
			hmac_md5_update(cur_salt->salt, cur_salt->salt_length, &ctx);
			hmac_md5_final(out, &ctx);
			if (memcmp(out, cur_salt->msgAuthenticationParameters, 12) == 0)
				cracked[index] = 1;
			else
				cracked[index] = 0;
		} else if (cur_salt->authProtocol == 2) {
			snmp_usm_password_to_key_sha((const uint8_t *)saved_key[index],
					strlen(saved_key[index]),
					cur_salt->engineID,
					cur_salt->engineLength, authKey);
			hmac_sha1(authKey, 20, cur_salt->salt, cur_salt->salt_length, out, 12);
			if (memcmp(out, cur_salt->msgAuthenticationParameters, 12) == 0)
				cracked[index] = 1;
			else
				cracked[index] = 0;
		} else if (cur_salt->authProtocol == 0) {
			cracked[index] = 0;
			snmp_usm_password_to_key_md5((const uint8_t *)saved_key[index],
					strlen(saved_key[index]),
					cur_salt->engineID,
					cur_salt->engineLength, authKey);
			hmac_md5_init_rfc2104(authKey, 16, &ctx);
			hmac_md5_update(cur_salt->salt, cur_salt->salt_length, &ctx);
			hmac_md5_final(out, &ctx);
			if (memcmp(out, cur_salt->msgAuthenticationParameters, 12) == 0) {
				cracked[index] = 1;
				continue;
			}
			snmp_usm_password_to_key_sha((const uint8_t *)saved_key[index],
					strlen(saved_key[index]),
					cur_salt->engineID,
					cur_salt->engineLength, authKey);
			hmac_sha1(authKey, 20, cur_salt->salt, cur_salt->salt_length, out, 12);
			if (memcmp(out, cur_salt->msgAuthenticationParameters, 12) == 0)
				cracked[index] = 1;
		}
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (cracked[index])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return cracked[index];
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void snmp_set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_snmp = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_HUGE_INPUT,
/* FIXME: Should report authProtocol as a tunable cost */
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		fmt_default_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		snmp_set_key,
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
