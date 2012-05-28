/*
 * mskrb5_fmt.c
 *
 * MS Kerberos 5 "PA ENC TIMESTAMP" by magnum
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
 * Input format is 'user:$mskrb5$user$realm$checksum$timestamp'
 *
 * For compatibility with (possible) future attacks, there are fields for
 * username and realm but they are not used in this attack so they can be
 * empty. Example:
 *
 * user:$mskrb5$$$02E837D06B2AC76891F388D9CC36C67A$2A9785BF5036C45D3843490BF9C228E8C18653E10CE58D7F8EF119D2EF4F92B1803B1451
 *
 * OMP is supported and scales very well now.
 *
 * This  software is Copyright © 2011 magnum, and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
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

#define FORMAT_LABEL       "mskrb5"
#define FORMAT_NAME        "MS Kerberos 5 AS-REQ Pre-Auth"
#define ALGORITHM_NAME     "mskrb5"
#define BENCHMARK_COMMENT  ""
#define BENCHMARK_LENGTH   0
#define PLAINTEXT_LENGTH   125
#define CRYPT_BINARY_SIZE  8
#define BINARY_SIZE        0
#define MAX_REALMLEN       20
#define MAX_USERLEN        15
#define CHECKSUM_SIZE      16
#define TIMESTAMP_SIZE     36
#define KEY_SIZE           16
#define SALT_SIZE          (CHECKSUM_SIZE + TIMESTAMP_SIZE)
#define TOTAL_LENGTH       (10 + 2 * (CHECKSUM_SIZE + TIMESTAMP_SIZE) + MAX_REALMLEN + MAX_USERLEN)
#define PLAINTEXT_OFFSET   14

// these may be altered in init() if running OMP
#define MIN_KEYS_PER_CRYPT	    1
#define THREAD_RATIO            32
#ifdef _OPENMP
#define MAX_KEYS_PER_CRYPT	    0x10000
#else
#define MAX_KEYS_PER_CRYPT	    THREAD_RATIO
#endif

// Second and third plaintext will be replaced in init() under --encoding=utf8
static struct fmt_tests tests[] = {
	{"$mskrb5$john$JOHN.DOE.MS.COM$02E837D06B2AC76891F388D9CC36C67A$2A9785BF5036C45D3843490BF9C228E8C18653E10CE58D7F8EF119D2EF4F92B1803B1451", "fr2beesgr"},
	{"$mskrb5$$$98cd00b6f222d1d34e08fe0823196e0b$5937503ec29e3ce4e94a051632d0fff7b6781f93e3decf7dca707340239300d602932154", ""},
	{"$mskrb5$$$F4085BA458B733D8092E6B348E3E3990$034ACFC70AFBA542690B8BC912FCD7FED6A848493A3FF0D7AF641A263B71DCC72902995D", "frank"},
	{"$mskrb5$$$eb03b6fbcfe91f8346f3c0ae7e8abfe5$afcbe07c32c3450b37d0f2516354570fe7d3e78f829e77cdc1718adf612156507181f7da", "John"},
	{"$mskrb5$$$881c257ce5df7b11715a6a60436e075a$c80f4a5ec18e7c5f765fb9f00eda744a57483db500271369cf4752a67ca0e67f37c68402", "the"},
	{"$mskrb5$$$ef012e13c8b32448241091f4e1fdc805$354931c919580d4939421075bcd50f2527d092d2abdbc0e739ea72929be087de644cef8a", "Ripper"},
	{"$mskrb5$$$334ef74dad191b71c43efaa16aa79d88$34ebbad639b2b5a230b7ec1d821594ed6739303ae6798994e72bd13d5e0e32fdafb65413", "VeryveryveryloooooooongPassword"},
	{NULL}
};

static char (*saved_plain)[(PLAINTEXT_LENGTH+4)];
static int (*saved_len);
static char (*output)[CRYPT_BINARY_SIZE];
static HMACMD5Context (*saved_ctx);

static int keys_prepared;
static unsigned char *saltblob = NULL;
#define CHECKSUM  saltblob
#define TIMESTAMP &saltblob[CHECKSUM_SIZE]

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	int n = MIN_KEYS_PER_CRYPT * omp_get_max_threads();
	if (n < MIN_KEYS_PER_CRYPT)
		n = MIN_KEYS_PER_CRYPT;
	if (n > MAX_KEYS_PER_CRYPT)
		n = MAX_KEYS_PER_CRYPT;
	pFmt->params.min_keys_per_crypt = n;
	n = n * (n << 1) * THREAD_RATIO;
	if (n > MAX_KEYS_PER_CRYPT)
		n = MAX_KEYS_PER_CRYPT;
	pFmt->params.max_keys_per_crypt = n;
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	output = mem_calloc_tiny(sizeof(*output) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_ctx = mem_calloc_tiny(sizeof(*saved_ctx) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	if (options.utf8) {
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

static char *hex2bin(char *src, unsigned char *dst, int outsize)
{
	char *p, *pe;
	unsigned char *q, *qe, ch, cl;

	pe = src + strlen(src);
	qe = dst + outsize;
	p = src, q = dst;
	while (p < pe && q < qe && (ch = atoi16[ARCH_INDEX(*p++)]) != 0x7f) {
		if (ch == 0x7f)
			return p;
		cl = atoi16[ARCH_INDEX(*p++)];
		if (cl == 0x7f)
			return p;
		*q++ = (ch << 4) | cl;
	}
	return p;
}

static void *get_salt(char *ciphertext)
{
	static unsigned char *salt;
	char *data = ciphertext, *p;
	int n;

	if (!salt) salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	// skip the $mskrb5$ string
	data += 8;

	// skip the user field
	p = strchr(data, '$');
	if (!p)
		return NULL;
	data = p + 1;

	// skip the realm field
	p = strchr(data, '$');
	if (!p)
		return NULL;
	data = p + 1;

	// read the checksum
	p = strchr(data, '$');
	if (!p)
		return NULL;
	n = (p - data);
	if (n != 2 * CHECKSUM_SIZE)
		return NULL;
	p = hex2bin(data, salt, CHECKSUM_SIZE);
	data = p + 1;

	// read the encrypted timestamp
	p = hex2bin(data, &salt[CHECKSUM_SIZE], TIMESTAMP_SIZE);
	if (*p || p - data != TIMESTAMP_SIZE * 2)
		return NULL;

	return salt;
}

static void set_salt(void *salt)
{
	saltblob = salt;
}

static char *split(char *ciphertext, int index)
{
	static char out[TOTAL_LENGTH + 1];
	char *data;

	strncpy(out, ciphertext, sizeof(out));
	out[TOTAL_LENGTH] = 0;
	data = out;

	// the $mskrb5$ string
	data += 8;

	// the user field (may be empty for this attack)
	data = strchr(data, '$') + 1;

	// the realm field (may be empty for this attack)
	data = strchr(data, '$') + 1;

	strlwr(data);

	return out;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *data = ciphertext, *p;

	if (strncmp(ciphertext, "$mskrb5$", 8) != 0)
		return 0;
	data += 8;

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
	if (!p || p - data != 2 * CHECKSUM_SIZE)
		return 0;
	data = p + 1;

	// encrypted timestamp
	p += strlen(data) + 1;
	if (*p || p - data != TIMESTAMP_SIZE * 2)
		return 0;

	return 1;
}

static void set_key(char *key, int index)
{
	saved_len[index] = strlen(key);
	memcpy(saved_plain[index], key, saved_len[index] + 1);
	keys_prepared = 0;
}

static char *get_key(int index)
{
	return (char *) saved_plain[index];
}

static void crypt_all(int count)
{
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
		unsigned char K3[KEY_SIZE], cleartext[PLAINTEXT_OFFSET + CRYPT_BINARY_SIZE];
		HMACMD5Context ctx;
		RC4_KEY key;
		// key set up with K1 is stored in saved_ctx[index]
		// CHECKSUM and TIMESTAMP are just defines, they are actually
		// concatenated to saltblob[]

		// K3 = HMAC-MD5(K1, CHECKSUM)
		memcpy(&ctx, &saved_ctx[i], sizeof(ctx));
		hmac_md5_update(CHECKSUM, CHECKSUM_SIZE, &ctx);
		hmac_md5_final(K3, &ctx);

		// RC4(K3, TIMESTAMP) decrypt part of the timestamp
		RC4_set_key(&key, KEY_SIZE, K3);
		RC4(&key, PLAINTEXT_OFFSET + CRYPT_BINARY_SIZE, TIMESTAMP,
		    cleartext);

		// 15th byte and on is our partial binary
		memcpy(output[i], &cleartext[PLAINTEXT_OFFSET], CRYPT_BINARY_SIZE);
	}
}

static int cmp_all(void *binary, int count)
{
	int index;
	char *tst;

	for (index = 0; index < count; index++) {
		tst = (char*)(output[index]);
		if (tst[0] == '2' && tst[1] == '0'
		    && (tst[2] <= '9' && tst[2] >= '0')
		    && (tst[3] <= '9' && tst[3] >= '0')
		    && (tst[4] == '0' || tst[4] == '1')
		    && (tst[5] <= '9' && tst[5] >= '0')
		    && (tst[6] <= '3' && tst[6] >= '0')
		    && (tst[7] <= '9' && tst[7] >= '0')
		    )
			return 1;
	}
	return 0;
}

static int cmp_one(void *binary, int index)
{
	char *tst = (char*)(output[index]);

	return (tst[0] == '2' && tst[1] == '0'
		    && (tst[2] <= '9' && tst[2] >= '0')
		    && (tst[3] <= '9' && tst[3] >= '0')
		    && (tst[4] == '0' || tst[4] == '1')
		    && (tst[5] <= '9' && tst[5] >= '0')
		    && (tst[6] <= '3' && tst[6] >= '0')
		    && (tst[7] <= '9' && tst[7] >= '0')
	    );
}

static int cmp_exact(char *source, int index)
{
	HMACMD5Context ctx;
	unsigned char K2[KEY_SIZE], K3[KEY_SIZE];
	RC4_KEY key;
	unsigned char cleartext[TIMESTAMP_SIZE];

	// K1 is stored in saved_ctx[index]
	// CHECKSUM and TIMESTAMP are just defines, they are actually
	// concatenated to saltblob[]

	// K3 = HMAC-MD5(K1, CHECKSUM)
	memcpy(&ctx, &saved_ctx[index], sizeof(ctx));
	hmac_md5_update(CHECKSUM, CHECKSUM_SIZE, &saved_ctx[index]);
	hmac_md5_final(K3, &saved_ctx[index]);

	// Decrypt the timestamp with the derived key K3
	RC4_set_key(&key, KEY_SIZE, K3);
	RC4(&key, TIMESTAMP_SIZE, TIMESTAMP, cleartext);

	// create checksum K2 = HMAC-MD5(K1, cleartext)
	hmac_md5_update(cleartext, TIMESTAMP_SIZE, &ctx);
	hmac_md5_final(K2, &ctx);

	// Compare our checksum with the input checksum
	return (!memcmp(K2, CHECKSUM, CHECKSUM_SIZE));
}

static int salt_hash(void *salt)
{
	return (*(ARCH_WORD_32 *) salt) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_mskrb5 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		split,
		fmt_default_binary,
		get_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
