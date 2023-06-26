/*
 * Kerberos 5 etype 23 "PA ENC TIMESTAMP" by magnum
 *
 * Previously called mskrb5 because I had the idea it was Micro$oft specific.
 *
 * Pcap file -> input file:
 * 1. tshark -r capture.pcapng -T pdml  > ~/capture.pdml
 * 2. krbng2john.py ~/capture.pdml > krb5.in
 * 3. Run john on krb5.in
 *
 * PA_DATA_ENC_TIMESTAMP = Checksum[16 bytes] . Enc_Timestamp[36 bytes]
 *                          -> encode as:
 *                         HexChecksum[32 chars], HexTimestamp[72 chars]
 *
 * Legacy input format:
 *   user:$mskrb5$user$realm$HexChecksum$HexTimestamp
 *
 * New input format from krb2john.py (the above is still supported),
 * note the lack of a separator between HexTimestamp and HexChecksum:
 *   user:$krb5pa$etype$user$realm$salt$HexTimestampHexChecksum
 *
 * user, realm and salt are unused in this format.
 *
 * This attacks a known-plaintext vulnerability in AS_REQ pre-auth packets. The
 * known plaintext is a UTC timestamp in the format 20081120171510Z. Only if
 * this indicate a match we decrypt the whole timestamp and calculate our own
 * checksum to be really sure.
 *
 * The plaintext attack combined with re-using key setup was said to result in
 * more than 60% speedup. This was confirmed using John the Ripper and variants
 * of this code.
 *
 * http://www.ietf.org/rfc/rfc4757.txt
 * http://www.securiteam.com/windowsntfocus/5BP0H0A6KM.html
 *
 * OMP is supported and scales very well now.
 *
 * This software is Copyright (c) 2011-2012 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_krb5pa_md5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_krb5pa_md5);
#else

#include <string.h>
#include <ctype.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "formats.h"
#include "options.h"
#include "common.h"
#include "unicode.h"
#include "md5.h"
#include "hmacmd5.h"
#include "md4.h"
#include "rc4.h"

#define FORMAT_LABEL       "krb5pa-md5"
#define FORMAT_NAME        "Kerberos 5 AS-REQ Pre-Auth etype 23"
#define FORMAT_TAG         "$krb5pa$"
#define FORMAT_TAG2        "$mskrb5$"
#define FORMAT_TAG_LEN     (sizeof(FORMAT_TAG)-1)

#define ALGORITHM_NAME     "MD4 HMAC-MD5 RC4 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT  ""
#define BENCHMARK_LENGTH   7
#define PLAINTEXT_LENGTH   125
#define MAX_REALMLEN       64
#define MAX_USERLEN        64
#define MAX_SALTLEN        128
#define TIMESTAMP_SIZE     36
#define CHECKSUM_SIZE      16
#define KEY_SIZE           16
#define BINARY_SIZE        CHECKSUM_SIZE
#define BINARY_ALIGN       4
#define SALT_SIZE          sizeof(struct salt_t)
#define SALT_ALIGN         4
#define TOTAL_LENGTH       (14 + 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) + MAX_REALMLEN + MAX_USERLEN + MAX_SALTLEN)

#define MIN_KEYS_PER_CRYPT 1
#define MAX_KEYS_PER_CRYPT 32

#ifndef OMP_SCALE
#define OMP_SCALE          2 // Tuned w/ MKPC for core i7
#endif

// Second and third plaintext will be replaced in init() under come encodings
static struct fmt_tests tests[] = {
	{"$krb5pa$23$user$realm$salt$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7daeb03b6fbcfe91f8346f3c0ae7e8abfe5", "John"},
	{"$mskrb5$john$JOHN.DOE.MS.COM$02E837D06B2AC76891F388D9CC36C67A$2A9785BF5036C45D3843490BF9C228E8C18653E10CE58D7F8EF119D2EF4F92B1803B1451", "fr2beesgr"},
	{"$mskrb5$user1$EXAMPLE.COM$08b5adda3ab0add14291014f1d69d145$a28da154fa777a53e23059647682eee2eb6c1ada7fb5cad54e8255114270676a459bfe4a", "openwall"},
	{"$mskrb5$hackme$EXAMPLE.NET$e3cdf70485f81a85f7b59a4c1d6910a3$6e2f6705551a76f84ec2c92a9dd0fef7b2c1d4ca35bf1b02423359a3ecaa19bdf07ed0da", "openwall@123"},
	{"$mskrb5$$$98cd00b6f222d1d34e08fe0823196e0b$5937503ec29e3ce4e94a051632d0fff7b6781f93e3decf7dca707340239300d602932154", ""},
	{"$mskrb5$$$F4085BA458B733D8092E6B348E3E3990$034ACFC70AFBA542690B8BC912FCD7FED6A848493A3FF0D7AF641A263B71DCC72902995D", "frank"},
	{"$mskrb5$user$realm$eb03b6fbcfe91f8346f3c0ae7e8abfe5$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7da", "John"},
	{"$mskrb5$$$881c257ce5df7b11715a6a60436e075a$c80f4a5ec18e7c5f765fb9f00eda744a57483db500271369cf4752a67ca0e67f37c68402", "the"},
	{"$mskrb5$$$ef012e13c8b32448241091f4e1fdc805$354931c919580d4939421075bcd50f2527d092d2abdbc0e739ea72929be087de644cef8a", "Ripper"},
	{"$mskrb5$$$334ef74dad191b71c43efaa16aa79d88$34ebbad639b2b5a230b7ec1d821594ed6739303ae6798994e72bd13d5e0e32fdafb65413", "VeryveryveryloooooooongPassword"},
	// repeat first hash in exactly the same form that is used in john.pot
	{"$krb5pa$23$$$$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7daeb03b6fbcfe91f8346f3c0ae7e8abfe5", "John"},
	// http://www.exumbraops.com/layerone2016/party (sample.krb.pcap, hash extracted by krb2john.py)
	{"$krb5pa$23$$$$4b8396107e9e4ec963c7c2c5827a4f978ad6ef943f87637614c0f31b2030ad1115d636e1081340c5d6612a3e093bd40ce8232431", "P@$$w0rd123"},
	// ADSecurityOrg-MS14068-Exploit-KRBPackets.pcapng, https://adsecurity.org/?p=676
	{"$krb5pa$23$$$$3d973b3833953655d019abff1a98ea124d98d94170fb77574f3cf6d0e6a7eded9f3e4bb37ec9fb64b55df7d9aceb6e19c1711983", "TheEmperor99!"},
	{NULL}
};

static struct salt_t {
	uint32_t checksum[CHECKSUM_SIZE / sizeof(uint32_t)];
	unsigned char timestamp[TIMESTAMP_SIZE];
} *cur_salt;

static char (*saved_plain)[(PLAINTEXT_LENGTH+4)];
static int (*saved_len);
static uint32_t (*output)[BINARY_SIZE / sizeof(uint32_t)];
static HMACMD5Context (*saved_ctx);

static int keys_prepared;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
	saved_len   = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_len));
	output      = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*output));
	saved_ctx   = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_ctx));

	if (options.target_enc == UTF_8) {
		tests[1].plaintext = "\xC3\xBC"; // German u-umlaut in UTF-8
		tests[1].ciphertext = "$mskrb5$$$958db4ddb514a6cc8be1b1ccf82b0191$090408357a6f41852d17f3b4bb4634adfd388db1be64d3fe1a1d75ee4338d2a4aea387e5";
		tests[2].plaintext = "\xC3\x9C\xC3\x9C"; // 2x uppercase of them
		tests[2].ciphertext = "$mskrb5$$$057cd5cb706b3de18e059912b1f057e3$fe2e561bd4e42767e972835ea99f08582ba526e62a6a2b6f61364e30aca7c6631929d427";
	} else {
		if (CP_to_Unicode[0xfc] == 0x00fc) {
			tests[1].plaintext = "\xFC";     // German u-umlaut in many ISO-8859-x
			tests[1].ciphertext = "$mskrb5$$$958db4ddb514a6cc8be1b1ccf82b0191$090408357a6f41852d17f3b4bb4634adfd388db1be64d3fe1a1d75ee4338d2a4aea387e5";
		}
		if (CP_to_Unicode[0xdc] == 0x00dc) {
			tests[2].plaintext = "\xDC\xDC"; // 2x uppercase of them
			tests[2].ciphertext = "$mskrb5$$$057cd5cb706b3de18e059912b1f057e3$fe2e561bd4e42767e972835ea99f08582ba526e62a6a2b6f61364e30aca7c6631929d427";
		}
	}
}

static void done(void)
{
	MEM_FREE(saved_ctx);
	MEM_FREE(output);
	MEM_FREE(saved_len);
	MEM_FREE(saved_plain);
}

static void *get_salt(char *ciphertext)
{
	static struct salt_t salt;
	char *p;
	int i;

	p = strrchr(ciphertext, '$') + 1;
	for (i = 0; i < TIMESTAMP_SIZE; i++) {
		salt.timestamp[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	for (i = 0; i < CHECKSUM_SIZE; i++) {
		((unsigned char*)salt.checksum)[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return (void*)&salt;
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TOTAL_LENGTH + 1];
	char *data;

	if (!strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG_LEN)) {
		char in[TOTAL_LENGTH + 1];
		char *c, *t;

		strnzcpy(in, ciphertext, sizeof(in));

		t = strrchr(in, '$'); *t++ = 0;
		c = strrchr(in, '$'); *c++ = 0;

		snprintf(out, sizeof(out), "%s23$$$$%s%s", FORMAT_TAG, t, c);
	} else {
		char *tc;

		tc = strrchr(ciphertext, '$');

		snprintf(out, sizeof(out), "%s23$$$$%s", FORMAT_TAG, ++tc);
	}

	data = out + strlen(out) - 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) - 1;
	strlwr(data);

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char *binary;
	char *p;
	int i;

	if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	p = strrchr(ciphertext, '$') + 1;
	p += 2 * TIMESTAMP_SIZE;

	for (i = 0; i < CHECKSUM_SIZE; i++) {
		binary[i] =
			(atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return (void*)binary;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *data = ciphertext, *p;

	if (!strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG_LEN)) {
		data += FORMAT_TAG_LEN;

		// user field
		p = strchr(data, '$');
		if (!p || p - data > MAX_USERLEN)
			return 0;
		data = p + 1;

		// realm field
		p = strchr(data, '$');
		if (!p || p - data > MAX_REALMLEN)
			return 0;
		data = p + 1;

		// checksum
		p = strchr(data, '$');
		if (!p || p - data != 2 * CHECKSUM_SIZE ||
		    strspn(data, HEXCHARS_all) != p - data)
			return 0;
		data = p + 1;

		// encrypted timestamp
		p += strlen(data) + 1;
		if (*p || p - data != TIMESTAMP_SIZE * 2 ||
		    strspn(data, HEXCHARS_all) != p - data)
			return 0;

		return 1;
	} else if (!strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)) {
		data += FORMAT_TAG_LEN;
		if (strncmp(data, "23$", 3)) return 0;
		data += 3;
		// user field
		p = strchr(data, '$');
		if (!p || p - data > MAX_USERLEN)
			return 0;
		data = p + 1;

		// realm field
		p = strchr(data, '$');
		if (!p || p - data > MAX_REALMLEN)
			return 0;
		data = p + 1;

		// salt field
		p = strchr(data, '$');
		if (!p || p - data > MAX_SALTLEN)
			return 0;
		data = p + 1;

		// timestamp+checksum
		p += strlen(data) + 1;
		if (*p || p - data != (TIMESTAMP_SIZE + CHECKSUM_SIZE) * 2 ||
		    strspn(data, HEXCHARS_all) != p - data)
			return 0;

		return 1;
	}
	return 0;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_plain[index], key, sizeof(*saved_plain));
	keys_prepared = 0;
}

static char *get_key(int index)
{
	return (char *) saved_plain[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	const unsigned char one[] = { 1, 0, 0, 0 };
	int i;

	if (!keys_prepared) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (i = 0; i < count; i++) {
			int len;
			unsigned char K[KEY_SIZE];
			unsigned char K1[KEY_SIZE];
			// K = MD4(UTF-16LE(password)), ordinary 16-byte NTLM hash
			len = E_md4hash((unsigned char *) saved_plain[i], saved_len[i], K);

			if (len <= 0)
				((char*)(saved_plain[i]))[-len] = 0;	// match truncation

			// K1 = HMAC-MD5(K, 1)
			// 1 is encoded as little endian in 4 bytes (0x01000000)
			hmac_md5(K, (unsigned char *) &one, 4, K1);

			// We do key setup of the next HMAC_MD5 here. rest in inner loop
			hmac_md5_init_K16(K1, &saved_ctx[i]);
		}
		keys_prepared = 1;
	}

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (i = 0; i < count; i++) {
		unsigned char K3[KEY_SIZE], cleartext[TIMESTAMP_SIZE];
		HMACMD5Context ctx;
		// key set up with K1 is stored in saved_ctx[i]

		// K3 = HMAC-MD5(K1, CHECKSUM)
		memcpy(&ctx, &saved_ctx[i], sizeof(ctx));
		hmac_md5_update((unsigned char*)cur_salt->checksum,
		                CHECKSUM_SIZE, &ctx);
		hmac_md5_final(K3, &ctx);

		// Decrypt part of the timestamp with the derived key K3
		RC4_single(K3, KEY_SIZE, cur_salt->timestamp, 16, cleartext);

		// Bail out unless we see known plaintext
		if (cleartext[14] == '2' && cleartext[15] == '0') {
			// Decrypt the rest of the timestamp
			RC4_single(K3, KEY_SIZE, cur_salt->timestamp,
			           TIMESTAMP_SIZE, cleartext);
			if (cleartext[28] == 'Z') {
				// create checksum K2 = HMAC-MD5(K1, plaintext)
				memcpy(&ctx, &saved_ctx[i], sizeof(ctx));
				hmac_md5_update(cleartext, TIMESTAMP_SIZE, &ctx);
				hmac_md5_final((unsigned char*)output[i], &ctx);
			}
		} else {
			output[i][0] = 0;
		}
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*(uint32_t*)binary == output[index][0])
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, output[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

#define COMMON_GET_HASH_VAR output
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	return (((struct salt_t*)salt)->checksum[0]) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_krb5pa_md5 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_ENC,
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
