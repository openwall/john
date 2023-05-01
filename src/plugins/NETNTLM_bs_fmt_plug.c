/*
 * NETNTLM_fmt.c -- NTLM Challenge/Response
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2007
 * and placed in the public domain.
 *
 * Modified for performance, support for Extended Session Security, OMP
 * and UTF-8, by magnum 2010-2011.

 * Modified for using Bitsliced DES by Deepika Dutta Mishra
 * <dipikadutta at gmail.com> in 2013, no rights reserved.
 *
 * This algorithm is designed for performing brute-force cracking of the NTLM
 * (version 1) challenge/response pairs exchanged during network-based
 * authentication attempts [1]. The captured challenge/response pairs from these
 * attempts should be stored using the L0phtCrack 2.0 LC format, specifically:
 * username:unused:unused:lm response:ntlm response:challenge. For example:
 *
 * CORP\Administrator:::25B2B477CE101D83648BB087CE7A1C217F51C7FC64C0EBB1:
 * C8BD0C1630A9ECF7A95F494A8F0B2CB4A3F25B1225514304:1122334455667788
 *
 * It should be noted that a NTLM authentication response is not same as a NTLM
 * password hash, which can be extracted using tools such as FgDump [2]. NTLM
 * responses can be gathered via normal network capture or via tools which
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with
 * some trickery to convince the user to connect to it. I leave what that
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB
 * broadcasts, IE, Outlook, social engineering, ...).
 *
 * [1] http://davenport.sourceforge.net/ntlm.html#theNtlmResponse
 * [2] http://www.foofus.net/~fizzgig/fgdump/
 * [3] http://ettercap.sourceforge.net/
 * [4] http://www.oxid.it/cain.html
 * [5] http://www.foofus.net/jmk/smbchallenge.html
 *
 * This version supports Extended Session Security. This is what
 * is used when the "LM" hash ends in 32 zeros:
 *
 * DOMAIN\User:::c70e4fb229437ef300000000000000000000000000000000:
 * abf7762caf2b1bbfc5cfc1f46665249f049e0af72ae5b5a9:24ca92fdab441aa4
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_NETNTLM_old;
#elif FMT_REGISTERS_H
john_register_one(&fmt_NETNTLM_old);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "DES_std.h"
#include "DES_bs.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "md5.h"
#include "unicode.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "netntlm-naive"
#define FORMAT_NAME          "NTLMv1 C/R"
#define FORMAT_TAG           "$NETNTLM$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME       "MD4 DES (ESS MD5) " DES_BS_ALGORITHM_NAME " naive"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     7
#define PLAINTEXT_LENGTH     125
#define BINARY_SIZE          24
#define BINARY_ALIGN         4
#define PARTIAL_BINARY_SIZE  8
#define SALT_SIZE            8
#define SALT_ALIGN           4
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         (10 + 2 * 2 * SALT_SIZE + CIPHERTEXT_LENGTH)

#define MIN_KEYS_PER_CRYPT      DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT      DES_BS_DEPTH

static struct fmt_tests tests[] = {
	{"", "FooBarGerg",                    {"User", "", "", "lm-hash", "35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A", "1122334455667788"} },
	{"$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "g3rg3g3rg3g3rg3"},
	{"$NETNTLM$1122334455667788$E463FAA5D868ECE20CAE622474A2F440A652D642156AF863", "M1xedC4se%^&*@)##(blahblah!@#"},
	{"$NETNTLM$c75c20bff9baa71f4765f360625700b0$81f5ecd8a77fe819f7f6689a08a27ac705fc2e1bb00cecb2", "password"},
	{"$NETNTLM$1122334455667788$35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A", "FooBarGerg"},
	{"$NETNTLM$1122334455667788$A4765EBFE83D345A7CB1660B8899251905164029F8086DDE", "visit www.foofus.net"},
	{"$NETNTLM$24ca92fdab441aa4c70e4fb229437ef3$abf7762caf2b1bbfc5cfc1f46665249f049e0af72ae5b5a9", "longpassword"},
	{"$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233", "cory21"},
	{"", "g3rg3g3rg3g3rg3",               {"User", "", "", "lm-hash", "BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "1122334455667788"} },
	{"", "M1xedC4se%^&*@)##(blahblah!@#", {"User", "", "", "lm-hash", "E463FAA5D868ECE20CAE622474A2F440A652D642156AF863", "1122334455667788"} },
	{"", "visit www.foofus.net",          {"User", "", "", "lm-hash", "A4765EBFE83D345A7CB1660B8899251905164029F8086DDE", "1122334455667788"} },
	{"", "password",                      {"ESS", "", "", "4765f360625700b000000000000000000000000000000000", "81f5ecd8a77fe819f7f6689a08a27ac705fc2e1bb00cecb2", "c75c20bff9baa71f"} },
	{"", "cory21",                        {"User", "", "", "lm-hash", "B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233", "1122334455667788"} },
	{NULL}
};

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static uchar (*output)[PARTIAL_BINARY_SIZE];
static uchar (*saved_key)[21]; // NT hash
static uchar *challenge;
static int keys_prepared;
static void set_salt(void *salt);

static void init(struct fmt_main *self)
{
	/* LM =2 for DES encryption with no salt and no iterations */
	DES_bs_init(2, DES_bs_cpt);
#if DES_bs_mt
	self->params.min_keys_per_crypt = DES_bs_min_kpc;
	self->params.max_keys_per_crypt = DES_bs_max_kpc;
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	output = mem_calloc(self->params.max_keys_per_crypt, sizeof(*output));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(output);
	MEM_FREE(saved_len);
	MEM_FREE(saved_plain);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)!=0) return 0;

	if ((strlen(ciphertext) != 74) && (strlen(ciphertext) != 90)) return 0;

	if ((ciphertext[25] != '$') && (ciphertext[41] != '$')) return 0;

	for (pos = &ciphertext[FORMAT_TAG_LEN]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos != '$') return 0;

	for (pos++;atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (!*pos && ((pos - ciphertext - 26 == CIPHERTEXT_LENGTH) ||
	        (pos - ciphertext - 42 == CIPHERTEXT_LENGTH)))
		return 1;
	else
		return 0;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	char clientChal[17];
	char *srv_challenge = split_fields[3];
	char *nethashv2     = split_fields[4];
	char *cli_challenge = split_fields[5];

	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN))
		return split_fields[1];
	if (!srv_challenge || !nethashv2 || !cli_challenge)
		return split_fields[1];

	if (strlen(nethashv2) != CIPHERTEXT_LENGTH)
		return split_fields[1];

	// this string suggests we have an improperly formatted NTLMv2
	if (!strncmp(&nethashv2[32], "0101000000000000", 16))
		return split_fields[1];

	// Handle ESS (8 byte client challenge in "LM" field padded with zeros)
	if (strlen(srv_challenge) == 48 && !strncmp(&srv_challenge[16],
	        "00000000000000000000000000000000", 32)) {
		memcpy(clientChal, srv_challenge,16);
		clientChal[16] = 0;
	}
	else
		clientChal[0] = 0;
	cp = mem_alloc(FORMAT_TAG_LEN+strlen(cli_challenge)+strlen(clientChal)+1+strlen(nethashv2)+1);
	sprintf(cp, "%s%s%s$%s", FORMAT_TAG, cli_challenge, clientChal, nethashv2);

	if (valid(cp,self)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[TOTAL_LENGTH + 1];

	memset(out, 0, TOTAL_LENGTH + 1);
	strcpy(out, ciphertext);
	strlwr(&out[FORMAT_TAG_LEN]); /* Exclude: $NETNTLM$ */

	return out;
}

static uint32_t *generate_des_format(uchar* binary)
{
	static uint32_t out[6];
	ARCH_WORD block[6];
	int chr, src,dst,i;
	uchar value, mask;
	ARCH_WORD *ptr;

	memset(block, 0, sizeof(block));

	for (chr = 0; chr < 24; chr=chr + 8)
	{
		dst = 0;
		for (i=0; i<8; i++)
		{
			value = binary[chr + i];
			mask = 0x80;

			for (src = 0; src < 8; src++) {
				if (value & mask)
					block[(chr/4) + (dst>>5)] |= 1U << (dst & 0x1F);
				mask >>= 1;
				dst++;
			}
		}
	}

	/* Apply initial permutation on ciphertext blocks */
	for (i=0; i<6; i=i+2)
	{
		ptr = DES_do_IP(&block[i]);
		out[i] = ptr[1];
		out[i+1] = ptr[0];
	}

	return out;
}

static void *get_binary(char *ciphertext)
{
	uchar binary[BINARY_SIZE];
	int i;
	uint32_t *ptr;

	ciphertext = strrchr(ciphertext, '$') + 1;
	for (i=0; i<BINARY_SIZE; i++) {
		binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
		binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
	}

	/* Set binary in DES format */
	ptr = generate_des_format(binary);
	return ptr;
}

inline static void setup_des_key(unsigned char key_56[], int index)
{
	char key[8];

	/* Right shift key bytes by 1 to bring in openssl format */
	/* Each byte of key is xored with 0x80 to pass check for 0 in DES_bs_set_key() */

	key[0] = (key_56[0] >> 1) | 0x80;
	key[1] = (((key_56[0] << 7) | (key_56[1] >> 1)) >>1) | 0x80;
	key[2] = (((key_56[1] << 6) | (key_56[2] >> 2)) >>1) | 0x80;
	key[3] = (((key_56[2] << 5) | (key_56[3] >> 3)) >>1) | 0x80;
	key[4] = (((key_56[3] << 4) | (key_56[4] >> 4)) >>1) | 0x80;
	key[5] = (((key_56[4] << 3) | (key_56[5] >> 5)) >>1) | 0x80;
	key[6] = (((key_56[5] << 2) | (key_56[6] >> 6)) >>1) | 0x80;
	key[7] = ((key_56[6] << 1) >>1 ) | 0x80;

	DES_bs_set_key((char*)key, index);
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i;

	if (!keys_prepared) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (i = 0; i < count; i++) {
			int len;

			/* Generate 16-byte NTLM hash */
			len = E_md4hash((uchar *) saved_plain[i], saved_len[i],
			        saved_key[i]);

			if (len <= 0)
				saved_plain[i][-len] = 0; // match truncation

			/* NULL-padding the 16-byte hash to 21-bytes is made
			   in cmp_exact if needed */

			setup_des_key(saved_key[i], i);
		}
		keys_prepared = 1;
	}

	/* Bitsliced des encryption */
	DES_bs_crypt_plain(count);

	return count;
}

static int cmp_all(void *binary, int count)
{
	return DES_bs_cmp_all((uint32_t *)binary, count);
}

static int cmp_one(void *binary, int index)
{
	return DES_bs_cmp_one((uint32_t *)binary, 32, index);
}

static int cmp_exact(char *source, int index)
{
	uint32_t *binary = get_binary(source);

	if (!DES_bs_cmp_one(binary, 64, index))
		return 0;

	setup_des_key(&saved_key[index][7], 0);
	DES_bs_crypt_plain(1);
	if (!DES_bs_cmp_one(&binary[2], 64, 0))
	{
		setup_des_key(saved_key[0], 0);
		DES_bs_crypt_plain(1);
		return 0;
	}

	/* NULL-pad 16-byte NTLM hash to 21-bytes (postponed until now) */
	memset(&saved_key[index][16], 0, 5);

	setup_des_key(&saved_key[index][14], 0);
	DES_bs_crypt_plain(1);
	if (!DES_bs_cmp_one(&binary[4], 64, 0))
	{
		setup_des_key(saved_key[0], 0);
		DES_bs_crypt_plain(1);
		return 0;
	}

	setup_des_key(saved_key[0], 0);
	DES_bs_crypt_plain(1);
	return 1;
}

static void *get_salt(char *ciphertext)
{
	static uchar *binary_salt;
	int i, cnt,j;
	unsigned char temp[SALT_SIZE];

	if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	if (ciphertext[25] == '$') {
		// Server challenge
		ciphertext += FORMAT_TAG_LEN;
		for (i = 0; i < SALT_SIZE; ++i)
			binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	} else {
		uchar es_salt[2*SALT_SIZE], k1[2*SALT_SIZE];
		MD5_CTX ctx;

		ciphertext += FORMAT_TAG_LEN;
		// Extended Session Security,
		// Concatenate Server & Client challenges
		for (i = 0;i < 2 * SALT_SIZE; ++i)
			es_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

		// MD5 the concatenated challenges, result is our key
		MD5_Init(&ctx);
		MD5_Update(&ctx, es_salt, 16);
		MD5_Final((void*)k1, &ctx);
		memcpy(binary_salt, k1, SALT_SIZE); // but only 8 bytes of it
	}

	/* Apply IP to salt */
	memset(temp, 0, SALT_SIZE);
	for (i = 0; i < 64; i++) {
		cnt = DES_IP[i ^ 0x20];
		j = (uchar)((binary_salt[cnt >> 3] >> (7 - (cnt & 7))) & 1);
		temp[i/8] |= j << (7 - (i % 8));
	}

	memcpy(binary_salt, temp, SALT_SIZE);
	return (void*)binary_salt;
}

static void set_salt(void *salt)
{
	challenge = salt;
	DES_bs_generate_plaintext(challenge);
}

static void netntlm_set_key(char *key, int index)
{
	saved_len[index] = strnzcpyn(saved_plain[index], key, sizeof(*saved_plain));
	keys_prepared = 0;
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int salt_hash(void *salt)
{
	return *(uint32_t *)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_NETNTLM_old = {
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
#if DES_BS
		FMT_BS |
#if DES_bs_mt
		FMT_OMP |
#endif
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
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
		netntlm_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			DES_bs_get_hash_0,
			DES_bs_get_hash_1,
			DES_bs_get_hash_2,
			DES_bs_get_hash_3,
			DES_bs_get_hash_4,
			DES_bs_get_hash_5,
			DES_bs_get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
