/*
 * NETLMv2_fmt.c -- LMv2 Challenge/Response
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2008
 * and placed in the public domain.
 *
 * Performance fixes, OMP and utf-8 support by magnum 2010-2011
 *
 * This algorithm is designed for performing brute-force cracking of the LMv2
 * challenge/response sets exchanged during network-based authentication
 * attempts [1]. The captured challenge/response set from these attempts
 * should be stored using the following format:
 *
 * USERNAME::DOMAIN:SERVER CHALLENGE:LMv2 RESPONSE:CLIENT CHALLENGE
 *
 * For example:
 * Administrator::WORKGROUP:1122334455667788:6759A5A7EFB25452911DE7DE8296A0D8:F503236B200A5B3A
 *
 * It should be noted that a LMv2 authentication response is not same as a LM
 * password hash, which can be extracted using tools such as FgDump [2]. In
 * fact, a NTLM hash and not a LM hash is used within the LMv2 algorithm. LMv2
 * challenge/response authentication typically takes place when the GPO
 * "Network Security: LAN Manager authentication level" is configured to a setting
 * that enforces the use of NTLMv2, such as "Send NTLMv2 response only\refuse
 * LM & NTLM."
 *
 * LMv2 responses can be gathered via normal network capture or via tools which
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with
 * some trickery to convince the user to connect to it. I leave what that
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB
 * broadcasts, IE, Outlook, social engineering, ...).
 *
 * [1] http://davenport.sourceforge.net/ntlm.html#theLmv2Response
 * [2] http://www.foofus.net/fizzgig/fgdump/
 * [3] http://ettercap.sourceforge.net/
 * [4] http://www.oxid.it/cain.html
 * [5] http://www.foofus.net/jmk/smbchallenge.html
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
#include "unicode.h"

#include "md5.h"
#include "hmacmd5.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "netlmv2"
#define FORMAT_NAME          "LMv2 C/R MD4 HMAC-MD5"
#define ALGORITHM_NAME       "32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     0
#define PLAINTEXT_LENGTH     125 /* lmcons.h - PWLEN (256) ? 127 ? */
#define USERNAME_LENGTH      60 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH        45 /* lmcons.h - CNLEN / DNLEN */
#define BINARY_SIZE          16
#define CHALLENGE_LENGTH     32
#define SALT_SIZE            16 + 1 + 2 * (USERNAME_LENGTH + DOMAIN_LENGTH) + 1
#define CIPHERTEXT_LENGTH    32
#define TOTAL_LENGTH         12 + USERNAME_LENGTH + DOMAIN_LENGTH + CHALLENGE_LENGTH + CIPHERTEXT_LENGTH

// these may be altered in init() if running OMP
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define OMP_SCALE		1536

static struct fmt_tests tests[] = {
  {"$NETLMv2$ADMINISTRATORFOODOM$1122334455667788$6F64C5C1E35F68DD80388C0F00F34406$F0F3FF27037AA69F", "1337adminPASS"},
  {"$NETLMv2$USER1$1122334455667788$B1D163EA5881504F3963DC50FCDC26C1$EB4D9E8138149E20", "foobar"},
  {"$NETLMv2$ATEST$1122334455667788$83B59F1536D3321DBF1FAEC14ADB1675$A1E7281FE8C10E53", "SomeFancyP4$$w0rdHere"},
  {"", "1337adminPASS",         {"FOODOM\\Administrator", "", "",       "1122334455667788", "6F64C5C1E35F68DD80388C0F00F34406", "F0F3FF27037AA69F"} },
  {"", "1337adminPASS",         {"administrator",         "", "FOODOM", "1122334455667788", "6F64C5C1E35F68DD80388C0F00F34406", "F0F3FF27037AA69F"} },
  {"", "foobar",                {"user1",                 "", "",       "1122334455667788", "B1D163EA5881504F3963DC50FCDC26C1", "EB4D9E8138149E20"} },
  {"", "SomeFancyP4$$w0rdHere", {"aTest",                 "", "",       "1122334455667788", "83B59F1536D3321DBF1FAEC14ADB1675", "A1E7281FE8C10E53"} },
  {NULL}
};

static uchar (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static uchar (*output)[BINARY_SIZE];
static HMACMD5Context (*saved_ctx);
static int keys_prepared;
static unsigned char *challenge;

#if !defined(uint16) && !defined(HAVE_UINT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define uint16 unsigned short
#endif /* SIZEOF_SHORT != 4 */
#endif

#if !defined(int16) && !defined(HAVE_INT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define int16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define int16 short
#endif /* SIZEOF_SHORT != 4 */
#endif

#include "byteorder.h"

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	output = mem_calloc_tiny(sizeof(*output) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_ctx = mem_calloc_tiny(sizeof(*saved_ctx) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int netlmv2_valid(char *ciphertext, struct fmt_main *self)
{
  char *pos, *pos2;

  if (ciphertext == NULL) return 0;
  else if (strncmp(ciphertext, "$NETLMv2$", 9)!=0) return 0;

  pos = &ciphertext[9];

  /* Validate Username and Domain Length */
  for (pos2 = pos; strncmp(pos2, "$", 1) != 0; pos2++)
    if ((unsigned char)*pos2 < 0x20)
      return 0;

  if ( !(*pos2 && (pos2 - pos <= USERNAME_LENGTH + DOMAIN_LENGTH)) )
    return 0;

  /* Validate Server Challenge Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
    return 0;

  /* Validate LMv2 Response Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
    return 0;

  /* Validate Client Challenge Length */
  pos2++; pos = pos2;
  for (; atoi16[ARCH_INDEX(*pos2)] != 0x7F; pos2++);
  if (pos2 - pos != CHALLENGE_LENGTH / 2)
    return 0;

  return 1;
}

static char *netlmv2_prepare(char *split_fields[10], struct fmt_main *self)
{
	char *srv_challenge = split_fields[3];
	char *nethashv2     = split_fields[4];
	char *cli_challenge = split_fields[5];
	char *login = split_fields[0];
	char *uid = split_fields[2];
	char *identity = NULL, *tmp;

	if (!strncmp(split_fields[1], "$NETLMv2$", 9))
		return split_fields[1];
	if (!split_fields[0]||!split_fields[2]||!split_fields[3]||!split_fields[4]||!split_fields[5])
		return split_fields[1];

	/* DOMAIN\USER: -or- USER::DOMAIN: */
	if ((tmp = strstr(login, "\\")) != NULL) {
		identity = (char *) mem_alloc(strlen(login));
		strcpy(identity, tmp + 1);

		/* Upper-Case Username - Not Domain */
		enc_strupper(identity);

		strncat(identity, login, tmp - login);
	}
	else {
		identity = (char *) mem_alloc(strlen(login) + strlen(uid) + 1);
		strcpy(identity, login);

		enc_strupper(identity);

		strcat(identity, uid);
	}
	tmp = (char *) mem_alloc(9 + strlen(identity) + 1 + strlen(srv_challenge) + 1 + strlen(nethashv2) + 1 + strlen(cli_challenge) + 1);
	sprintf(tmp, "$NETLMv2$%s$%s$%s$%s", identity, srv_challenge, nethashv2, cli_challenge);
	MEM_FREE(identity);

	if (netlmv2_valid(tmp, self)) {
		char *cp = str_alloc_copy(tmp);
		MEM_FREE(tmp);
		return cp;
	}
	MEM_FREE(tmp);
	return split_fields[1];
}


static char *netlmv2_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];
  char *pos = NULL;
  int identity_length = 0;

  /* Calculate identity length */
  for (pos = ciphertext + 9; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 9);

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, strlen(ciphertext));
  strlwr(&out[10 + identity_length]); /* Exclude: $NETLMv2$USERDOMAIN$ */

  return out;
}

static void *netlmv2_get_binary(char *ciphertext)
{
  static uchar *binary;
  char *pos = NULL;
  int i, identity_length;

  if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

  for (pos = ciphertext + 9; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 9);

  ciphertext += 9 + identity_length + 1 + CHALLENGE_LENGTH / 2 + 1;
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }

  return binary;
}

/* Calculate the LMv2 response for the given challenge, using the
   specified authentication identity (username and domain), password
   and client nonce.
*/
static void netlmv2_crypt_all(int count)
{
	int i = 0;

#ifdef _OPENMP
#pragma omp parallel for
	for(i = 0; i < count; i++)
#endif
	{
		unsigned char ntlm_v2_hash[16];
		HMACMD5Context ctx; // can't be moved above the OMP pragma

		if (!keys_prepared) {
			int len;
			unsigned char ntlm[16];
			/* Generate 16-byte NTLM hash */
			len = E_md4hash(saved_plain[i], saved_len[i], ntlm);

			// We do key setup of the next HMAC_MD5 here (once per salt)
			hmac_md5_init_K16(ntlm, &saved_ctx[i]);

			if (len <= 0)
				saved_plain[i][-len] = 0; // match truncation
		}

		/* HMAC-MD5(Username + Domain, NTLM Hash) */
		memcpy(&ctx, &saved_ctx[i], sizeof(ctx));
		hmac_md5_update(&challenge[17], (int)challenge[16], &ctx);
		hmac_md5_final(ntlm_v2_hash, &ctx);

		/* Generate 16-byte non-client nonce portion of LMv2 Response */
		/* HMAC-MD5(Challenge + Nonce, NTLMv2 Hash) + Nonce */
		hmac_md5(ntlm_v2_hash, challenge, 16, (unsigned char*)output[i]);
	}
	keys_prepared = 1;
}

static int netlmv2_cmp_all(void *binary, int count)
{
	int index;
	for(index=0; index<count; index++)
		if (!memcmp(output[index], binary, BINARY_SIZE))
			return 1;
	return 0;
}

static int netlmv2_cmp_one(void *binary, int index)
{
	return !memcmp(output[index], binary, BINARY_SIZE);
}

static int netlmv2_cmp_exact(char *source, int index)
{
	return !memcmp(output[index], netlmv2_get_binary(source), BINARY_SIZE);
}

/* We're essentially using three salts, but we're going to pack it into a single blob for now.
   |Client Challenge (8 Bytes)|Server Challenge (8 Bytes)|Unicode(Username (<=20).Domain (<=15))
*/
static void *netlmv2_get_salt(char *ciphertext)
{
  static unsigned char *binary_salt;
  unsigned char identity[USERNAME_LENGTH + DOMAIN_LENGTH + 1];
  UTF16 identity_ucs2[USERNAME_LENGTH + DOMAIN_LENGTH + 1];
  int i, identity_length;
  int identity_ucs2_length;
  char *pos = NULL;

  if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

  /* Calculate identity length */
  for (pos = ciphertext + 9; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 9);

  /* Convert identity (username + domain) string to NT unicode */
  strnzcpy((char *)identity, ciphertext + 9, sizeof(identity));
  identity_ucs2_length = enc_to_utf16((UTF16 *)identity_ucs2, USERNAME_LENGTH + DOMAIN_LENGTH, (UTF8 *)identity, identity_length) * sizeof(int16);

  if (identity_ucs2_length < 0) // Truncated at Unicode conversion.
	  identity_ucs2_length = strlen16((UTF16 *)identity_ucs2) * sizeof(int16);

  binary_salt[16] = (unsigned char)identity_ucs2_length;
  memcpy(&binary_salt[17], (char *)identity_ucs2, identity_ucs2_length);

  /* Set server challenge */
  ciphertext += 10 + identity_length;

  for (i = 0; i < 8; i++)
    binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  /* Set client challenge */
  ciphertext += 2 + CHALLENGE_LENGTH / 2 + CIPHERTEXT_LENGTH;

  for (i = 0; i < 8; ++i)
    binary_salt[i + 8] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  /* Return a concatenation of the server and client challenges and the identity value */
  return (void*)binary_salt;
}

static void netlmv2_set_salt(void *salt)
{
	challenge = salt;
}

static void netlmv2_set_key(char *key, int index)
{
	saved_len[index] = strlen(key);
	memcpy((char *)saved_plain[index], key, saved_len[index] + 1);
	keys_prepared = 0;
}

static char *netlmv2_get_key(int index)
{
  return (char *)saved_plain[index];
}

static int salt_hash(void *salt)
{
	// Hash the client challenge (in case server salt was spoofed)
	return (*(ARCH_WORD_32 *)salt+8) & (SALT_HASH_SIZE - 1);
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

struct fmt_main fmt_NETLMv2 = {
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
		netlmv2_prepare,
		netlmv2_valid,
		netlmv2_split,
		netlmv2_get_binary,
		netlmv2_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		netlmv2_set_salt,
		netlmv2_set_key,
		netlmv2_get_key,
		fmt_default_clear_keys,
		netlmv2_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		netlmv2_cmp_all,
		netlmv2_cmp_one,
		netlmv2_cmp_exact
	}
};
