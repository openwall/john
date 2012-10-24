/*
 * MSCHAPv2_fmt.c -- Microsoft PPP CHAP Extensions, Version 2
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2010
 * and placed in the public domain.
 *
 * Modified for performance, OMP and utf-8 support
 * by magnum 2010-2011
 *
 * Support for freeradius-wep-patch challenge/response format
 * added by Linus Lüssing in 2012 and is licensed under CC0/PD terms:
 *  To the extent possible under law, Linus Lüssing has waived all copyright
 *  and related or neighboring rights to this work. This work is published from: Germany.
 *
 *
 * This algorithm is designed for performing brute-force cracking of the
 * MSCHAPv2 challenge/response sets exchanged during network-based
 * authentication attempts. The captured challenge/response set from these
 * attempts should be stored using the following format:
 *
 * USERNAME:::AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * USERNAME::DOMAIN:AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * DOMAIN\USERNAME:::AUTHENTICATOR CHALLENGE:MSCHAPv2 RESPONSE:PEER CHALLENGE
 * :::MSCHAPv2 CHALLENGE:MSCHAPv2 RESPONSE:
 *
 * For example:
 * User:::5B5D7C7D7B3F2F3E3C2C602132262628:82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF:21402324255E262A28295F2B3A337C7E
 * domain\fred:::56d64cbe7bad61349a0b752335100eaf:d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b:7f8a466cff2a6bf0c80218bbf56d76bc
 *
 * http://freeradius.org/rfc/rfc2759.txt
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
#include "memory.h"

#include "sha.h"
#include <openssl/des.h>

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "mschapv2"
#define FORMAT_NAME          "MSCHAPv2 C/R MD4 DES"
#define ALGORITHM_NAME       "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     125 /* lmcons.h - PWLEN (256) ? 127 ? */
#define USERNAME_LENGTH      256 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH        15  /* lmcons.h - CNLEN / DNLEN */
#define PARTIAL_BINARY_SIZE  8
#define BINARY_SIZE          24
#define CHALLENGE_LENGTH     64
#define SALT_SIZE            8
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         13 + USERNAME_LENGTH + CHALLENGE_LENGTH + CIPHERTEXT_LENGTH

// these may be altered in init() if running OMP
#define MIN_KEYS_PER_CRYPT	1
#define THREAD_RATIO		256
#ifdef _OPENMP
#define MAX_KEYS_PER_CRYPT	0x10000
#else
#define MAX_KEYS_PER_CRYPT	THREAD_RATIO
#endif

static struct fmt_tests tests[] = {
  {"$MSCHAPv2$4c092fd3fd98236502e8591100046326$b912ce522524d33123a982cf330a57f8e953fa7974042b5d$6a4915d0ce61d42be533640a75391925$1111", "2222"},
  {"$MSCHAPv2$5B5D7C7D7B3F2F3E3C2C602132262628$82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF$21402324255E262A28295F2B3A337C7E$User", "clientPass"},
  {"$MSCHAPv2$d07054459a1fdbc266a006f0220e6fac$33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde$3545cb1d89b507a5de104435e81b14a4$testuser1", "Cricket8"},
  {"$MSCHAPv2$56d64cbe7bad61349a0b752335100eaf$d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b$7f8a466cff2a6bf0c80218bbf56d76bc$fred", "OMG!BBQ!11!one"}, /* domain\fred */
  {"$MSCHAPv2$b3c42db475b881d3c52ff3923d7b3bf8$f07c7a4eb391f5debe32d814679a5a69661b86b33227c4f8$6321f8649b971bd11ce8d5cb22a4a738$bOb", "asdblahblahblahblahblahblahblahblah"}, /* WorkGroup\bOb */
  {"$MSCHAPv2$d94e7c7972b2376b28c268583e162de7$eba25a3b04d2c7085d01f842e2befc91745c40db0f792356$0677ca7318fd7f65ae1b4f58c9f4f400$lameuser", ""}, /* no password */
  {"$MSCHAPv2$8710da60ebfc4cab$c4e3bb55904c966927ee68e5f1472e1f5d8ec165713b5360$$foo4", "bar4" },
  {"$MSCHAPv2$8710da60ebfc4cab$c4e3bb55904c966927ee68e5f1472e1f5d8ec165713b5360$$", "bar4" },

  /* Ettercap generated three test vectors */
  {"$MSCHAPv2$3D79CC8CDC0261D4$B700770725F87739ADB110B310D9A289CDBB550ADCA6CB86$solar", "solarisalwaysbusy"},
  {"$MSCHAPv2$BA75EB14EFBFBF25$ED8CC90FD40FAA2D6BCD0ABD0B1F562FD777DF6C5609C98B$lulu", "password"},
  {"$MSCHAPv2$95A87FA62EBCD2E3C8B09E1B448A6C72$ED8CC90FD40FAA2D6BCD0ABD0B1F562FD777DF6C5609C98B$E2AE0995EAAC6CEFF0D9757428B51509$lulu", "password"},

  {"", "clientPass",     {"User",        "", "",    "5B5D7C7D7B3F2F3E3C2C602132262628", "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "21402324255E262A28295F2B3A337C7E"} },
  {"", "Cricket8",       {"testuser1",   "", "",    "d07054459a1fdbc266a006f0220e6fac", "33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde", "3545cb1d89b507a5de104435e81b14a4"} },
  {"", "OMG!BBQ!11!one", {"domain\\fred", "", "",   "56d64cbe7bad61349a0b752335100eaf", "d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b", "7f8a466cff2a6bf0c80218bbf56d76bc"} }, /* domain\fred */
  {"", "",               {"lameuser", "", "domain", "d94e7c7972b2376b28c268583e162de7", "eba25a3b04d2c7085d01f842e2befc91745c40db0f792356", "0677ca7318fd7f65ae1b4f58c9f4f400"} }, /* no password */
  {"", "asdblahblahblahblahblahblahblahblah", {"WorkGroup\\bOb", "", "", "b3c42db475b881d3c52ff3923d7b3bf8", "f07c7a4eb391f5debe32d814679a5a69661b86b33227c4f8", "6321f8649b971bd11ce8d5cb22a4a738"} }, /* WorkGroup\bOb */

  {NULL}
};

static uchar (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static uchar (*saved_key)[21];
static uchar (*output)[PARTIAL_BINARY_SIZE];
static uchar *challenge;
static int keys_prepared;

#include "unicode.h"

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int n = MIN_KEYS_PER_CRYPT * omp_get_max_threads();
	if (n < MIN_KEYS_PER_CRYPT)
		n = MIN_KEYS_PER_CRYPT;
	if (n > MAX_KEYS_PER_CRYPT)
		n = MAX_KEYS_PER_CRYPT;
	self->params.min_keys_per_crypt = n;
	n = n * (n << 1) * THREAD_RATIO;
	if (n > MAX_KEYS_PER_CRYPT)
		n = MAX_KEYS_PER_CRYPT;
	self->params.max_keys_per_crypt = n;
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	output = mem_alloc_tiny(sizeof(*output) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int mschapv2_valid_long(char *ciphertext)
{
  char *pos, *pos2;

  if (ciphertext == NULL) return 0;
  else if (strncmp(ciphertext, "$MSCHAPv2$", 10)!=0) return 0;

  /* Validate Authenticator/Server Challenge Length */
  pos = &ciphertext[10];
  for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
    return 0;

  /* Validate MSCHAPv2 Response Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
    return 0;

  /* Validate Peer/Client Challenge Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
    return 0;

  /* Validate Username Length */
  if (strlen(++pos2) > USERNAME_LENGTH)
    return 0;

  return 1;
}

static int mschapv2_valid_short(char *ciphertext)
{
  char *pos, *pos2;

  if (ciphertext == NULL) return 0;
  else if (strncmp(ciphertext, "$MSCHAPv2$", 10)!=0) return 0;

  /* Validate MSCHAPv2 Challenge Length */
  pos = &ciphertext[10];
  for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 4)) )
    return 0;

  /* Validate MSCHAPv2 Response Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
    return 0;

  return 1;
}

static int mschapv2_valid(char *ciphertext, struct fmt_main *pFmt)
{
	return	mschapv2_valid_short(ciphertext) ||
		mschapv2_valid_long(ciphertext);
}

static char *mschapv2_prepare_long(char *split_fields[10])
{
  char *username, *cp;

  /* DOMAIN\USERNAME -or - USERNAME -- ignore DOMAIN */
  if ((username = strstr(split_fields[0], "\\")) == NULL)
    username = split_fields[0];
  else
    username++;

  cp = mem_alloc(1+8+1+strlen(split_fields[3])+1+strlen(split_fields[4])+1+strlen(split_fields[5])+1+strlen(username)+1);
  sprintf(cp, "$MSCHAPv2$%s$%s$%s$%s", split_fields[3], split_fields[4], split_fields[5], username);
  if (mschapv2_valid_long(cp)) {
    char *cp2 = str_alloc_copy(cp);
    MEM_FREE(cp);
    return cp2;
  }
  MEM_FREE(cp);
  return split_fields[1];
}

static char *mschapv2_prepare_short(char *split_fields[10])
{
  char *cp;

  cp = mem_alloc(1+8+1+strlen(split_fields[3])+1+strlen(split_fields[4])+1+1+1);
  sprintf(cp, "$MSCHAPv2$%s$%s$$", split_fields[3], split_fields[4]);
  if (mschapv2_valid_short(cp)) {
    char *cp2 = str_alloc_copy(cp);
    MEM_FREE(cp);
    return cp2;
  }
  MEM_FREE(cp);
  return split_fields[1];
}

static char *mschapv2_prepare(char *split_fields[10], struct fmt_main *pFmt)
{
  char *ret;

  if (!strncmp(split_fields[1], "$MSCHAPv2$", 10))
    ret = NULL;
  else if (split_fields[0] && split_fields[3] && split_fields[4] && split_fields[5] &&
           strlen(split_fields[3]) == CHALLENGE_LENGTH/2 &&
           strlen(split_fields[4]) == CIPHERTEXT_LENGTH &&
           strlen(split_fields[5]) == CHALLENGE_LENGTH/2)
    ret = mschapv2_prepare_long(split_fields);
  else if (split_fields[0] && split_fields[3] && split_fields[4] &&
           strlen(split_fields[3]) == CHALLENGE_LENGTH/4 &&
           strlen(split_fields[4]) == CIPHERTEXT_LENGTH)
    ret = mschapv2_prepare_short(split_fields);
  else
    ret = NULL;

  return ret ? ret : split_fields[1];
}

static char *mschapv2_split(char *ciphertext, int index)
{
  static char *out;
  int i, j = 0;

  if (!out) out = mem_alloc_tiny(TOTAL_LENGTH + 1, MEM_ALIGN_WORD);

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(out, ciphertext, strlen(ciphertext));

  /* convert hashes to lower-case - exclude $MSCHAPv2 and USERNAME */
  for (i = 10; i < TOTAL_LENGTH + 1 && j < 3; i++) {
    if (out[i] >= 'A' && out[i] <= 'Z')
      out[i] |= 0x20;
    else if (out[i] == '$')
      j++;
  }

  return out;
}

static void *mschapv2_get_binary(char *ciphertext)
{
  static uchar *binary;
  int i;

  if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

  if (mschapv2_valid_short(ciphertext))
    ciphertext += 10 + CHALLENGE_LENGTH / 4 + 1; /* Skip - $MSCHAPv2$, MSCHAPv2 Challenge */
  else
    ciphertext += 10 + CHALLENGE_LENGTH / 2 + 1; /* Skip - $MSCHAPv2$, Authenticator Challenge */

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

/* Calculate the MSCHAPv2 response for the given challenge, using the
   specified authentication identity (username), password and client
   nonce.
*/
static void mschapv2_crypt_all(int count)
{
	DES_key_schedule ks;
	int i;

	if (!keys_prepared) {
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for(i=0; i<count; i++) {
			int len;
			/* Generate 16-byte NTLM hash */
			len = E_md4hash((uchar *) saved_plain[i], saved_len[i], saved_key[i]);

			if (len <= 0)
				saved_plain[i][-len] = 0; // match if it was truncated

			/* NULL-padding the 16-byte hash to 21-bytes is made in cmp_exact if needed */
		}
		keys_prepared = 1;
	}

#ifdef _OPENMP
#pragma omp parallel for default(none) private(i, ks) shared(count, output, challenge, saved_key)
#endif
	for(i=0; i<count; i++) {

		/* Just do first DES for a partial binary */
		setup_des_key(saved_key[i], &ks);
		DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)output[i], &ks, DES_ENCRYPT);
	}
}

static int mschapv2_cmp_all(void *binary, int count)
{
	int index = 0;
	for(; index<count; index++)
		if (!memcmp(output[index], binary, PARTIAL_BINARY_SIZE))
			return 1;
	return 0;
}

static int mschapv2_cmp_one(void *binary, int index)
{
	return (!memcmp(output[index], binary, PARTIAL_BINARY_SIZE));
}

static int mschapv2_cmp_exact(char *source, int index)
{
	DES_key_schedule ks;
	uchar binary[24];

	/* NULL-pad 16-byte NTLM hash to 21-bytes (postponed until now) */
	memset(&saved_key[index][16], 0, 5);

	/* Split resultant value into three 7-byte thirds
	   DES-encrypt challenge using each third as a key
	   Concatenate three 8-byte resulting values to form 24-byte LM response
	*/
	setup_des_key(saved_key[index], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)binary, &ks, DES_ENCRYPT);
	setup_des_key(&saved_key[index][7], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[8], &ks, DES_ENCRYPT);
	setup_des_key(&saved_key[index][14], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[16], &ks, DES_ENCRYPT);

	return !memcmp(binary, mschapv2_get_binary(source), BINARY_SIZE);
}

static void mschapv2_get_challenge(const char *ciphertext, unsigned char *binary_salt)
{
  int i;
  const char *pos = ciphertext + 10;

  for (i = 0; i < SALT_SIZE; i++)
    binary_salt[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];
}

/* Either the cipherext already contains the MSCHAPv2 Challenge (4 Bytes) or
   we are going to calculate it via:
   sha1(|Peer/Client Challenge (8 Bytes)|Authenticator/Server Challenge (8 Bytes)|Username (<=256)|)
*/
static void *mschapv2_get_salt(char *ciphertext)
{
  static unsigned char *binary_salt;
  SHA_CTX ctx;
  unsigned char tmp[16];
  int i;
  char *pos = NULL;
  unsigned char digest[20];

  if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

  memset(binary_salt, 0, SALT_SIZE);
  memset(digest, 0, 20);

  if (mschapv2_valid_short(ciphertext)) {
    mschapv2_get_challenge(ciphertext, binary_salt);
    goto out;
  }

  SHA1_Init(&ctx);

  /* Peer Challenge */
  pos = ciphertext + 10 + 16*2 + 1 + 24*2 + 1; /* Skip $MSCHAPv2$, Authenticator Challenge and Response Hash */

  memset(tmp, 0, 16);
  for (i = 0; i < 16; i++)
    tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

  SHA1_Update(&ctx, tmp, 16);

  /* Authenticator Challenge */
  pos = ciphertext + 10; /* Skip $MSCHAPv2$ */

  memset(tmp, 0, 16);
  for (i = 0; i < 16; i++)
    tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

  SHA1_Update(&ctx, tmp, 16);

  /* Username - Only the user name (as presented by the peer and
     excluding any prepended domain name) is used as input to SHAUpdate()
  */
  pos = ciphertext + 10 + 16*2 + 1 + 24*2 + 1 + 16*2 + 1; /* Skip $MSCHAPv2$, Authenticator, Response and Peer */
  SHA1_Update(&ctx, pos, strlen(pos));

  SHA1_Final(digest, &ctx);
  memcpy(binary_salt, digest, SALT_SIZE);

out:
  return (void*)binary_salt;
}

static void mschapv2_set_salt(void *salt)
{
	challenge = salt;
}

static void mschapv2_set_key(char *key, int index)
{
	saved_len[index] = strlen(key);
	memcpy(saved_plain[index], key, saved_len[index] + 1);
	keys_prepared = 0;
}

static char *mschapv2_get_key(int index)
{
	return (char *)saved_plain[index];
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

struct fmt_main fmt_MSCHAPv2 = {
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
		mschapv2_prepare,
		mschapv2_valid,
		mschapv2_split,
		mschapv2_get_binary,
		mschapv2_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		mschapv2_set_salt,
		mschapv2_set_key,
		mschapv2_get_key,
		fmt_default_clear_keys,
		mschapv2_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		mschapv2_cmp_all,
		mschapv2_cmp_one,
		mschapv2_cmp_exact
	}
};
