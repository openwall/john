/*
 * NETNTLM_fmt.c -- NTLM Challenge/Response
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2007
 * and placed in the public domain.
 *
 * Modified for performance, support for Extended Session Security, OMP
 * and UTF-8, by magnum 2010-2011.
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
 * [1] http://davenport.sourceforge.net/ntlm.html#theNtLmResponse
 * [2] http://www.foofus.net/fizzgig/fgdump/
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

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"

#include "md5.h"
#include <openssl/des.h>

#include "unicode.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL		"netntlm"
#define FORMAT_NAME		"NTLMv1 C/R MD4 DES [ESS MD5]"
#define ALGORITHM_NAME		"netntlm"
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	125
#define BINARY_SIZE		24
#define PARTIAL_BINARY_SIZE	8
#define SALT_SIZE		8
#define CIPHERTEXT_LENGTH	48
#define TOTAL_LENGTH		(10 + 2 * 2 * SALT_SIZE + CIPHERTEXT_LENGTH)

// these may be altered in init() if running OMP
#define MIN_KEYS_PER_CRYPT	1
#define THREAD_RATIO		128
#ifdef _OPENMP
#define MAX_KEYS_PER_CRYPT	0x10000
#else
#define MAX_KEYS_PER_CRYPT	THREAD_RATIO
#endif

static struct fmt_tests tests[] = {
  {"$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "g3rg3g3rg3g3rg3"},
  {"$NETNTLM$1122334455667788$E463FAA5D868ECE20CAE622474A2F440A652D642156AF863", "M1xedC4se%^&*@)##(blahblah!@#"},
  {"$NETNTLM$c75c20bff9baa71f4765f360625700b0$81f5ecd8a77fe819f7f6689a08a27ac705fc2e1bb00cecb2", "password"},
  {"$NETNTLM$1122334455667788$35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A", "FooBarGerg"},
  {"$NETNTLM$1122334455667788$A4765EBFE83D345A7CB1660B8899251905164029F8086DDE", "visit www.foofus.net"},
  {"$NETNTLM$24ca92fdab441aa4c70e4fb229437ef3$abf7762caf2b1bbfc5cfc1f46665249f049e0af72ae5b5a9", "longpassword"},
  {"$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233", "cory21"},
  {"", "g3rg3g3rg3g3rg3",               {"User", "", "", "lm-hash", "BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "1122334455667788"} },
  {"", "M1xedC4se%^&*@)##(blahblah!@#", {"User", "", "", "lm-hash", "E463FAA5D868ECE20CAE622474A2F440A652D642156AF863", "1122334455667788"} },
  {"", "FooBarGerg",                    {"User", "", "", "lm-hash", "35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A", "1122334455667788"} },
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
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	output = mem_calloc_tiny(sizeof(*output) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
}

static int netntlm_valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos;

	if (strncmp(ciphertext, "$NETNTLM$", 9)!=0) return 0;

	if ((strlen(ciphertext) != 74) && (strlen(ciphertext) != 90)) return 0;

	if ((ciphertext[25] != '$') && (ciphertext[41] != '$')) return 0;

	for (pos = &ciphertext[9]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos != '$') return 0;

	for (pos++;atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (!*pos && ((pos - ciphertext - 26 == CIPHERTEXT_LENGTH) ||
	              (pos - ciphertext - 42 == CIPHERTEXT_LENGTH)))
		return 1;
	else
		return 0;
}

static char *netntlm_prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	char *cp;
	char clientChal[17];

	if (!strncmp(split_fields[1], "$NETNTLM$", 9))
		return split_fields[1];
	if (!split_fields[3]||!split_fields[4]||!split_fields[5])
		return split_fields[1];

	if (strlen(split_fields[4]) != CIPHERTEXT_LENGTH)
		return split_fields[1];

	// this string suggests we have an improperly formatted NTLMv2
	if (!strncmp(&split_fields[4][32], "0101000000000000", 16))
		return split_fields[1];

	// Handle ESS (8 byte client challenge in "LM" field padded with zeros)
	if (strlen(split_fields[3]) == 48 && !strncmp(&split_fields[3][16],
	    "00000000000000000000000000000000", 32)) {
		memcpy(clientChal, split_fields[3],16);
		clientChal[16] = 0;
	}
	else
		clientChal[0] = 0;
	cp = mem_alloc(9+strlen(split_fields[5])+strlen(clientChal)+1+strlen(split_fields[4])+1);
	sprintf(cp, "$NETNTLM$%s%s$%s", split_fields[5], clientChal, split_fields[4]);

	if (netntlm_valid(cp,pFmt)) {
		char *cp2 = str_alloc_copy(cp);
		free(cp);
		return cp2;
	}
	free(cp);
	return split_fields[1];
}

static char *netntlm_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, TOTAL_LENGTH);
  strlwr(&out[8]); /* Exclude: $NETNTLM$ */

  return out;
}

static void *netntlm_get_binary(char *ciphertext)
{
	static uchar *binary;
	int i;

	if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	ciphertext = strrchr(ciphertext, '$') + 1;
	for (i=0; i<BINARY_SIZE; i++) {
		binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
		binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
	}

	return binary;
}

static inline void setup_des_key(unsigned char key_56[], DES_key_schedule *ks)
{
  DES_cblock key;

  key[0] = key_56[0];
  key[1] = (key_56[0] << 7) | (key_56[1] >> 1);
  key[2] = (key_56[1] << 6) | (key_56[2] >> 2);
  key[3] = (key_56[2] << 5) | (key_56[3] >> 3);
  key[4] = (key_56[3] << 4) | (key_56[4] >> 4);
  key[5] = (key_56[4] << 3) | (key_56[5] >> 5);
  key[6] = (key_56[5] << 2) | (key_56[6] >> 6);
  key[7] = (key_56[6] << 1);

  DES_set_key(&key, ks);
}

static void netntlm_crypt_all(int count)
{
	DES_key_schedule ks;
	int i;

	if (!keys_prepared) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (i = 0; i < count; i++) {
			int len;

			/* Generate 16-byte NTLM hash */
			len = E_md4hash((uchar *) saved_plain[i], saved_len[i], saved_key[i]);

			if (len <= 0)
				saved_plain[i][-len] = 0; // match truncation

			/* Hash is NULL padded to 21-bytes in cmp_exact if needed */
		}
		keys_prepared = 1;
	}

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i, ks) shared(count, output, saved_key, challenge)
#endif
	for(i=0; i<count; i++) {
		/* Just do the first DES operation, for a partial binary */
		setup_des_key(saved_key[i], &ks);
		DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&output[i], &ks, DES_ENCRYPT);
	}
}

static int netntlm_cmp_all(void *binary, int count)
{
	int index;
	for(index=0; index<count; index++)
		if (!memcmp(output[index], binary, PARTIAL_BINARY_SIZE))
			return 1;
	return 0;
}

static int netntlm_cmp_one(void *binary, int index)
{
	return !memcmp(output[index], binary, PARTIAL_BINARY_SIZE);
}

static int netntlm_cmp_exact(char *source, int index)
{
	DES_key_schedule ks;
	uchar binary[24];

	/* Hash is NULL padded to 21-bytes (postponed until now) */
	memset(&saved_key[index][16], 0, 5);

	/* Split into three 7-byte segments for use as DES keys
	   Use each key to DES encrypt challenge
	   Concatenate output to for 24-byte NTLM response */

	setup_des_key(saved_key[index], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)binary, &ks, DES_ENCRYPT);
	setup_des_key(&saved_key[index][7], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[8], &ks, DES_ENCRYPT);
	setup_des_key(&saved_key[index][14], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[16], &ks, DES_ENCRYPT);

	return !memcmp(binary, netntlm_get_binary(source), BINARY_SIZE);
}

static void *netntlm_get_salt(char *ciphertext)
{
	static uchar *binary_salt;
	int i;

	if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	if (ciphertext[25] == '$') {
		// Server challenge
		ciphertext += 9;
		for (i = 0; i < SALT_SIZE; ++i)
			binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	} else {
		uchar es_salt[2*SALT_SIZE], k1[2*SALT_SIZE];
		MD5_CTX ctx;

		ciphertext += 9;
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
	return (void*)binary_salt;
}

static void netntlm_set_salt(void *salt)
{
	challenge = salt;
}

static void netntlm_set_key(char *key, int index)
{
	saved_len[index] = strlen(key);
	memcpy(saved_plain[index], key, saved_len[index] + 1);
	keys_prepared = 0;
}

static char *netntlm_get_key(int index)
{
	return saved_plain[index];
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32 *)salt & (SALT_HASH_SIZE - 1);
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return *(ARCH_WORD_32 *)output[index] & 0xF;
}

static int get_hash_1(int index)
{
	return *(ARCH_WORD_32 *)output[index] & 0xFF;
}

static int get_hash_2(int index)
{
	return *(ARCH_WORD_32 *)output[index] & 0xFFF;
}

static int get_hash_3(int index)
{
	return *(ARCH_WORD_32 *)output[index] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return *(ARCH_WORD_32 *)output[index] & 0xFFFFF;
}

struct fmt_main fmt_NETNTLM = {
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
	netntlm_prepare,
    netntlm_valid,
    netntlm_split,
    netntlm_get_binary,
    netntlm_get_salt,
    {
	    binary_hash_0,
	    binary_hash_1,
	    binary_hash_2,
	    binary_hash_3,
	    binary_hash_4
    },
    salt_hash,
    netntlm_set_salt,
    netntlm_set_key,
    netntlm_get_key,
    fmt_default_clear_keys,
    netntlm_crypt_all,
    {
	    get_hash_0,
	    get_hash_1,
	    get_hash_2,
	    get_hash_3,
	    get_hash_4
    },
    netntlm_cmp_all,
    netntlm_cmp_one,
    netntlm_cmp_exact
  }
};
