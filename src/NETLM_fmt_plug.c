/*
 * NETLM_fmt.c -- LM Challenge/Response
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2007
 * and placed in the public domain.
 *
 * Performance and OMP fixes by magnum 2011
 *
 * This algorithm is designed for performing brute-force cracking of the LM
 * challenge/response pairs exchanged during network-based authentication
 * attempts [1]. The captured challenge/response pairs from these attempts
 * should be stored using the L0phtCrack 2.0 LC format, specifically:
 * username:unused:unused:lm response:ntlm response:challenge. For example:
 *
 * CORP\Administrator:::25B2B477CE101D83648BB087CE7A1C217F51C7FC64C0EBB1::
 * C8BD0C1630A9ECF7A95F494A8F0B2CB4A3F25B1225514304:1122334455667788
 *
 * It should be noted that a LM authentication response is not same as a LM
 * password hash, which can be extracted using tools such as FgDump [2]. LM
 * responses can be gathered via normal network capture or via tools which
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with
 * some trickery to convince the user to connect to it. I leave what that
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB
 * broadcasts, IE, Outlook, social engineering, ...).
 *
 * [1] http://davenport.sourceforge.net/ntlm.html#theLmResponse
 * [2] http://www.foofus.net/~fizzgig/fgdump/
 * [3] http://ettercap.sourceforge.net/
 * [4] http://www.oxid.it/cain.html
 * [5] http://www.foofus.net/jmk/smbchallenge.html
 *
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_NETLM;
#elif FMT_REGISTERS_H
john_register_one(&fmt_NETLM);
#else

#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE            1024
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE            131072 // core i7 no HT
#endif
#endif // __MIC__
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "memory.h"
#include "unicode.h"

#include <openssl/des.h>
#include "memdbg.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "netlm"
#define FORMAT_NAME          "LM C/R"
#define ALGORITHM_NAME       "DES 32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     14
#define PARTIAL_BINARY_SIZE  8
#define BINARY_SIZE          24
#define BINARY_ALIGN         4
#define SALT_SIZE            8
#define SALT_ALIGN           4
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         8 + 2 * SALT_SIZE + CIPHERTEXT_LENGTH

#define MIN_KEYS_PER_CRYPT   1
#define MAX_KEYS_PER_CRYPT   1

static struct fmt_tests tests[] = {
  {"", "G3RG3P00!",      {"User", "", "", "6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "ntlm-hash", "1122334455667788"} },
  {"$NETLM$1122334455667788$16A7FDFE0CA109B937BFFB041F0E5B2D8B94A97D3FCA1A18", "HIYAGERGE"},
  {"$NETLM$1122334455667788$B3A1B87DBBD4DF3CFA296198DD390C2F4E2E93C5C07B1D8B", "MEDUSAFGDUMP12"},
  {"$NETLM$1122334455667788$0836F085B124F33895875FB1951905DD2F85252CC731BB25", "CORY21"},

  {"$NETLM$1122334455667788$6E1EC36D3417CE9E09A4424309F116C4C991948DAEB4ADAD", "G3RG3P00!"},
  {"", "HIYAGERGE",      {"User", "", "", "16A7FDFE0CA109B937BFFB041F0E5B2D8B94A97D3FCA1A18", "ntlm-hash", "1122334455667788"} },
  {"", "MEDUSAFGDUMP12", {"User", "", "", "B3A1B87DBBD4DF3CFA296198DD390C2F4E2E93C5C07B1D8B", "ntlm-hash", "1122334455667788"} },
  {"", "CORY21",         {"User", "", "", "0836F085B124F33895875FB1951905DD2F85252CC731BB25", "ntlm-hash", "1122334455667788"} },
  // repeat in exactly the same format that is used in john.pot (lower case hex)
  {"$NETLM$1122334455667788$0836f085b124f33895875fb1951905dd2f85252cc731bb25", "CORY21"},
  {NULL}
};

static uchar (*saved_key)[21];
static uchar (*saved_plain)[PLAINTEXT_LENGTH + 1];
static uchar (*output)[PARTIAL_BINARY_SIZE];
static uchar *challenge;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
	output = mem_calloc(self->params.max_keys_per_crypt, sizeof(*output));
}

static void done(void)
{
	MEM_FREE(output);
	MEM_FREE(saved_plain);
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
  char *pos;

  if (strncmp(ciphertext, "$NETLM$", 7)!=0) return 0;
  if (strlen(ciphertext) < TOTAL_LENGTH) return 0;
  if (ciphertext[23] != '$') return 0;

  if (strncmp(&ciphertext[24 + 2 * SALT_SIZE],
              "00000000000000000000000000000000", 32) == 0)
	  return 0; // This is NTLM ESS C/R

  for (pos = &ciphertext[24]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++)
	  ;
    if (!*pos && pos - ciphertext - 24 == CIPHERTEXT_LENGTH)
      return 1;
    else
      return 0;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	if (!strncmp(split_fields[1], "$NETLM$", 7))
		return split_fields[1];
	if (!split_fields[3]||!split_fields[4]||!split_fields[5])
		return split_fields[1];
	if (strlen(split_fields[3]) != CIPHERTEXT_LENGTH)
		return split_fields[1];

	// if LMresp == NTresp then it's NTLM-only, not LM
	if (!strncmp(split_fields[3], split_fields[4], 48))
		return split_fields[1];

	// this string suggests we have an improperly formatted NTLMv2
	if (strlen(split_fields[4]) > 31) {
		if (!strncmp(&split_fields[4][32], "0101000000000000", 16))
			return split_fields[1];
	}

	cp = mem_alloc(7+strlen(split_fields[3])+1+strlen(split_fields[5])+1);
	sprintf(cp, "$NETLM$%s$%s", split_fields[5], split_fields[3]);

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
  memcpy(out, ciphertext, TOTAL_LENGTH);
  strlwr(&out[6]); /* Exclude: $NETLM$ */

  return out;
}

static void *get_binary(char *ciphertext)
{
  static uchar *binary;
  int i;

  if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

  ciphertext+=24;
  for (i=0; i<BINARY_SIZE; i++)
  {
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

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	DES_key_schedule ks;
	int i = 0;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i, ks) shared(count, output, challenge, saved_key)
#endif
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for(i = 0; i < count; i++)
#endif
	{
		/* Just do a partial binary, the first DES operation */
		setup_des_key(saved_key[i], &ks);
		DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)output[i],
		                &ks, DES_ENCRYPT);
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#if defined(_OPENMP) || MAX_KEYS_PER_CRYPT > 1
	for(index=0; index<count; index++)
#endif
		if (!memcmp(output[index], binary, PARTIAL_BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(output[index], binary, PARTIAL_BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	DES_key_schedule ks;
	uchar binary[BINARY_SIZE];

	/* NULL-pad 16-byte LM hash to 21-bytes (we postponed it until now) */
	memset(&saved_key[index][16], 0, 5);

	/* Split padded LM hash into three 7-byte thirds
	   DES-encrypt challenge using each third as a key
	   Concatenate three 8-byte resulting values to form 24-byte LM response */
	setup_des_key(saved_key[index], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)binary, &ks, DES_ENCRYPT);
	setup_des_key(&saved_key[index][7], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[8], &ks, DES_ENCRYPT);
	setup_des_key(&saved_key[index][14], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[16], &ks, DES_ENCRYPT);

	return (!memcmp(binary, get_binary(source), BINARY_SIZE));
}

static void *get_salt(char *ciphertext)
{
  static unsigned char *binary_salt;
  int i;

  if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

  ciphertext += 7;
  for (i = 0; i < SALT_SIZE; ++i)
    binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  return (void*)binary_salt;
}

static void set_salt(void *salt)
{
	challenge = salt;
}

static void netlm_set_key(char *key, int index)
{
	const unsigned char magic[] = {0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25};
	DES_key_schedule ks;

	strncpy((char *)saved_plain[index], key, sizeof(saved_plain[index]));
	saved_plain[index][sizeof(saved_plain[index])-1] = 0;

	/* Upper-case password */
	enc_strupper((char*)saved_plain[index]);

	/* Generate 16-byte LM hash */
	setup_des_key(saved_plain[index], &ks);
	DES_ecb_encrypt((DES_cblock*)magic, (DES_cblock*)saved_key[index], &ks, DES_ENCRYPT);
	setup_des_key(&saved_plain[index][7], &ks);
	DES_ecb_encrypt((DES_cblock*)magic, (DES_cblock*)&saved_key[index][8], &ks, DES_ENCRYPT);

	/* NULL-padding the 16-byte LM hash to 21-bytes is done in cmp_exact */
}

static char *get_key(int index)
{
	return (char*)saved_plain[index];
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32 *)salt & (SALT_HASH_SIZE - 1);
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

static int get_hash_5(int index)
{
	return *(ARCH_WORD_32 *)output[index] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	return *(ARCH_WORD_32 *)output[index] & 0x7FFFFFF;
}

struct fmt_main fmt_NETLM = {
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
		FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		netlm_set_key,
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

#endif /* plugin stanza */
