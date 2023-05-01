/*
 * NETHALFLM_fmt.c
 * Written by DSK (Based on NetLM/NetNTLM patch by JoMo-Kun)
 * Performs brute-force cracking of the HalfLM challenge/response pairs.
 *
 * Modified for performance and OMP support by magnum 2011
 *
 * Storage Format:
 * domain\username:::lm response:nt response:challenge
 *
 *  NOTE, in loader.c, the format appeared to be domain\username:::lm response:challenge
 *  so that format has been built into the 'prepare' function (JimF).
 *
 * Code is in public domain.
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_NETHALFLM;
#elif FMT_REGISTERS_H
john_register_one(&fmt_NETHALFLM);
#else

#include <string.h>
#include <openssl/des.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "nethalflm"
#define FORMAT_NAME          "HalfLM C/R"
#define FORMAT_TAG           "$NETHALFLM$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME       "DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     7
#define PLAINTEXT_LENGTH     7
#define BINARY_SIZE          8
#define BINARY_ALIGN         4
#define SALT_SIZE            8
#define SALT_ALIGN           4
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         12 + 2 * SALT_SIZE + CIPHERTEXT_LENGTH
#define MIN_KEYS_PER_CRYPT	    1
#define MAX_KEYS_PER_CRYPT	    32

#ifndef OMP_SCALE
#define OMP_SCALE	64 // Tuned w/ MKPC for core i7
#endif

static struct fmt_tests tests[] = {
  {"", "G3RG3P00!", {"domain\\username", "", "", "6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "", "1122334455667788"} },
  {"$NETHALFLM$1122334455667788$6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "G3RG3P00!"},
  {"$NETHALFLM$1122334455667788$6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "g3rg3p0"},
  {"$NETHALFLM$1122334455667788$1354FD5ABF3B627B8B49587B8F2BBA0F9F6C5E420824E0A2", "zeeez@1"},

  {"", "G3RG3P0",   {"domain\\username", "", "", "6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "", "1122334455667788"} },
  {"", "ZEEEZ@1",   {"domain\\username", "", "", "1354FD5ABF3B627B8B49587B8F2BBA0F9F6C5E420824E0A2", "", "1122334455667788"} },
  // repeat last hash in exactly the same format that is used in john.pot
  {"$NETHALFLM$1122334455667788$1354fd5abf3b627b8b49587b8f2bba0f9f6c5e420824e0a2", "ZEEEZ@1"},
  {NULL}
};

static uchar (*saved_plain)[PLAINTEXT_LENGTH + 1];
static uchar (*saved_pre)[8];
static uchar (*output)[BINARY_SIZE];
static uchar *challenge;


static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
	saved_pre = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_pre));
	output = mem_calloc(self->params.max_keys_per_crypt,
	                    sizeof(*output));
}

static void done(void)
{
	MEM_FREE(output);
	MEM_FREE(saved_pre);
	MEM_FREE(saved_plain);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
  char *pos;

  if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)!=0) return 0;
  if (strlen(ciphertext) < TOTAL_LENGTH) return 0;
  if (ciphertext[27] != '$') return 0;

  if (strncmp(&ciphertext[28 + 2 * SALT_SIZE],
              "00000000000000000000000000000000", 32) == 0)
	  return 0; // This is NTLM ESS C/R

  for (pos = &ciphertext[28]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++)
	  ;
    if (!*pos && pos - ciphertext - 28 == CIPHERTEXT_LENGTH) {
	    return 1;
    }
    else
      return 0;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *tmp;
	char *srv_challenge = split_fields[3];
	char *nethashv2     = split_fields[4];
	char *cli_challenge = split_fields[5];

	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN))
		return split_fields[1];
	if (!srv_challenge || !nethashv2 || !cli_challenge)
		return split_fields[1];

	if (strlen(srv_challenge) != CIPHERTEXT_LENGTH)
		return split_fields[1];

	// if LMresp == NTresp then it's NTLM-only, not LM
	if (!strncmp(srv_challenge, nethashv2, 48))
		return split_fields[1];

	// this string suggests we have an improperly formatted NTLMv2
	if (strlen(nethashv2) > 31) {
		if (!strncmp(&nethashv2[32], "0101000000000000", 16))
			return split_fields[1];
	}

	tmp = (char *) mem_alloc(FORMAT_TAG_LEN + strlen(srv_challenge) + 1 + strlen(cli_challenge) + 1);
	sprintf(tmp, "%s%s$%s", FORMAT_TAG, cli_challenge, srv_challenge);

	if (valid(tmp,self)) {
		char *cp2 = str_alloc_copy(tmp);
		MEM_FREE(tmp);
		return cp2;
	}
	MEM_FREE(tmp);
	return split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
  static char out[TOTAL_LENGTH + 1] = {0};

  memcpy(out, ciphertext, TOTAL_LENGTH);
  strlwr(&out[FORMAT_TAG_LEN]); /* Exclude: $NETHALFLM$ */
  return out;
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		uint32_t dummy;
	} binary;
	int i;

	ciphertext+=28;
	for (i=0; i<BINARY_SIZE; i++)
	{
		binary.c[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
		binary.c[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
	}
	return binary.c;
}

inline static void setup_des_key(unsigned char key_56[], DES_key_schedule *ks)
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

  DES_set_key_unchecked(&key, ks);
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	DES_key_schedule ks;
	int i;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i, ks) shared(count, output, challenge, saved_pre)
#endif
	for (i=0; i<count; i++) {
		/* DES-encrypt challenge using the partial LM hash */
		setup_des_key(saved_pre[i], &ks);
		DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)output[i], &ks, DES_ENCRYPT);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!memcmp(output[index], binary, BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(output[index], binary, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(output[index], get_binary(source), BINARY_SIZE);
}

static void *get_salt(char *ciphertext)
{
	static union {
		unsigned char c[SALT_SIZE];
		uint32_t dummy;
	} out;
	int i;

	ciphertext += FORMAT_TAG_LEN;
	for (i = 0; i < SALT_SIZE; ++i) {
		out.c[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void*)out.c;
}

static void set_salt(void *salt)
{
	challenge = salt;
}

static void netsplitlm_set_key(char *key, int index)
{
	const unsigned char magic[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	DES_key_schedule ks;

	strnzcpy((char *)saved_plain[index], key, PLAINTEXT_LENGTH + 1);

	/* Upper-case password */
	enc_strupper((char *)saved_plain[index]);

	/* Generate first 8-bytes of LM hash */
	setup_des_key(saved_plain[index], &ks);
	DES_ecb_encrypt((DES_cblock*)magic, (DES_cblock*)saved_pre[index], &ks, DES_ENCRYPT);
}

static char *get_key(int index)
{
	return (char *)saved_plain[index];
}

static int salt_hash(void *salt)
{
	return *(uint32_t *)salt & (SALT_HASH_SIZE - 1);
}

#define COMMON_GET_HASH_VAR output
#include "common-get-hash.h"

struct fmt_main fmt_NETHALFLM = {
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
		FMT_8_BIT | FMT_TRUNC | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_OMP_BAD,
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
		netsplitlm_set_key,
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
#endif /* HAVE_LIBCRYPTO */
