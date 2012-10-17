/*
 * NETNTLMv2_fmt.c -- NTLMv2 Challenge/Response
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2009
 * and placed in the public domain.
 *
 * Modified for performance, OMP and utf-8 support by magnum 2010-2011
 *
 * This algorithm is designed for performing brute-force cracking of the NTLMv2
 * challenge/response sets exchanged during network-based authentication
 * attempts [1]. The captured challenge/response set from these attempts
 * should be stored using the following format:
 *
 * USERNAME::DOMAIN:SERVER CHALLENGE:NTLMv2 RESPONSE:CLIENT CHALLENGE
 *
 * For example:
 * ntlmv2test::WORKGROUP:1122334455667788:07659A550D5E9D02996DFD95C87EC1D5:0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000
 *
 * It should be noted that a NTLMv2 authentication response is not same as a NTLM
 * password hash, which can be extracted using tools such as FgDump [2]. NTLMv2
 * challenge/response authentication typically takes place when the GPO
 * "Network Security: LAN Manager authentication level" is configured to a setting
 * that enforces the use of NTLMv2, such as "Send NTLMv2 response only\refuse
 * LM & NTLM."
 *
 * NTLMv2 responses can be gathered via normal network capture or via tools which
 * perform layer 2 attacks, such as Ettercap [3] and Cain [4]. The responses can
 * also be harvested using a modified Samba service [5] in conjunction with
 * some trickery to convince the user to connect to it. I leave what that
 * trickery may actually be as an exercise for the reader (HINT: Karma, NMB
 * broadcasts, IE, Outlook, social engineering, ...).
 *
 * [1] http://davenport.sourceforge.net/ntlm.html#theNtlmv2Response
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

#include "md5.h"
#include "hmacmd5.h"

#include "unicode.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL		"netntlmv2"
#define FORMAT_NAME		"NTLMv2 C/R MD4 HMAC-MD5"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	0
#define PLAINTEXT_LENGTH	125 /* lmcons.h - PWLEN (256) ? 127 ? */
#define USERNAME_LENGTH		60 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH		45 /* lmcons.h - CNLEN / DNLEN */
#define BINARY_SIZE		16
#define SERVER_CHALL_LENGTH	16
#define CLIENT_CHALL_LENGTH_MAX	1024 /* FIXME - Max Target Information Size Unknown */
#define SALT_SIZE_MAX		2 * USERNAME_LENGTH + 2 * DOMAIN_LENGTH + 3 + SERVER_CHALL_LENGTH/2 + CLIENT_CHALL_LENGTH_MAX/2
#define CIPHERTEXT_LENGTH	32
#define TOTAL_LENGTH		12 + USERNAME_LENGTH + DOMAIN_LENGTH + SERVER_CHALL_LENGTH + CLIENT_CHALL_LENGTH_MAX + CIPHERTEXT_LENGTH

// these may be altered in init() if running OMP
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#define OMP_SCALE		3072

static struct fmt_tests tests[] = {
  {"$NETNTLMv2$NTLMV2TESTWORKGROUP$1122334455667788$07659A550D5E9D02996DFD95C87EC1D5$0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000", "password"},
  {"$NETNTLMv2$TESTUSERW2K3ADWIN7$1122334455667788$989B96DC6EAB529F72FCBA852C0D5719$01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000", "testpass"},
  {"$NETNTLMv2$USERW2K3ADWIN7$1122334455667788$5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9$0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
  {"$NETNTLMv2$USER1W2K3ADWIN7$1122334455667788$027EF88334DAA460144BDB678D4F988D$010100000000000092809B1192AACA01E01B519CB0248776000000000200120057004F0052004B00470052004F00550050000000000000000000", "SomeLongPassword1BlahBlah"},
  {"$NETNTLMv2$TEST_USERW2K3ADWIN7$1122334455667788$A06EC5ED9F6DAFDCA90E316AF415BA71$010100000000000036D3A13292AACA01D2CD95757A0836F9000000000200120057004F0052004B00470052004F00550050000000000000000000", "TestUser's Password"},
  {"$NETNTLMv2$USER1Domain$1122334455667788$5E4AB1BF243DCA304A00ADEF78DC38DF$0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000", "password"},
  {"", "password",                  {"TESTWORKGROUP\\NTlmv2", "", "",              "1122334455667788","07659A550D5E9D02996DFD95C87EC1D5","0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"} },
  {"", "password",                  {"NTlmv2",                "", "TESTWORKGROUP", "1122334455667788","07659A550D5E9D02996DFD95C87EC1D5","0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"} },
  {"", "testpass",                  {"TestUser",              "", "W2K3ADWIN7",    "1122334455667788","989B96DC6EAB529F72FCBA852C0D5719","01010000000000002EC51CEC91AACA0124576A744F198BDD000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
  {"", "password",                  {"user",                  "", "W2K3ADWIN7",    "1122334455667788","5BD1F32D8AFB4FB0DD0B77D7DE2FF7A9","0101000000000000309F56FE91AACA011B66A7051FA48148000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
  {"", "SomeLongPassword1BlahBlah", {"W2K3ADWIN7\\user1",     "", "",              "1122334455667788","027EF88334DAA460144BDB678D4F988D","010100000000000092809B1192AACA01E01B519CB0248776000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
  {"", "TestUser's Password",       {"W2K3ADWIN7\\TEST_USER", "", "",              "1122334455667788","A06EC5ED9F6DAFDCA90E316AF415BA71","010100000000000036D3A13292AACA01D2CD95757A0836F9000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
  {"", "password",                  {"USER1",                 "", "Domain",        "1122334455667788","5E4AB1BF243DCA304A00ADEF78DC38DF","0101000000000000BB50305495AACA01338BC7B090A62856000000000200120057004F0052004B00470052004F00550050000000000000000000"} },
  {NULL}
};

static uchar (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static uchar (*output)[BINARY_SIZE];
static HMACMD5Context (*saved_ctx);
static uchar *challenge;
static int keys_prepared;

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

static int netntlmv2_valid(char *ciphertext, struct fmt_main *self)
{
  char *pos, *pos2;

  if (ciphertext == NULL) return 0;
  else if (strncmp(ciphertext, "$NETNTLMv2$", 11)!=0) return 0;

  pos = &ciphertext[11];

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

  if ( !(*pos2 && (pos2 - pos == SERVER_CHALL_LENGTH)) )
    return 0;

  /* Validate NTLMv2 Response Length */
  pos2++; pos = pos2;
  for (; strncmp(pos2, "$", 1) != 0; pos2++)
    if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
      return 0;

  if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
    return 0;

  /* Validate Client Challenge Length */
  pos2++; pos = pos2;
  for (; atoi16[ARCH_INDEX(*pos2)] != 0x7F; pos2++);
  if ((pos2 - pos > CLIENT_CHALL_LENGTH_MAX) || (pos2 - pos < 28))
	  return 0;

  return 1;
}

static char *netntlmv2_prepare(char *split_fields[10], struct fmt_main *self)
{
	char *srv_challenge = split_fields[3];
	char *nethashv2     = split_fields[4];
	char *cli_challenge = split_fields[5];
	char *login = split_fields[0];
	char *uid = split_fields[2];
	char *identity = NULL, *tmp;

	if (!strncmp(split_fields[1], "$NETNTLMv2$", 11))
		return split_fields[1];
	if (!split_fields[0]||!split_fields[2]||!split_fields[3]||!split_fields[4]||!split_fields[5])
		return split_fields[1];

	/* DOMAIN\USER: -or- USER::DOMAIN: */
	if ((tmp = strstr(login, "\\")) != NULL) {
		identity = (char *) mem_alloc(strlen(login));
		strcpy(identity, tmp + 1);

		/* Upper-Case Username - Not Domain */
		enc_strupper((char *)identity);

		strncat(identity, login, tmp - login);
	}
	else {
		identity = (char *) mem_alloc(strlen(login) + strlen(uid) + 1);
		strcpy(identity, login);

		enc_strupper((char *)identity);

		strcat(identity, uid);
	}
	tmp = (char *) mem_alloc(11 + strlen(identity) + 1 + strlen(srv_challenge) + 1 + strlen(nethashv2) + 1 + strlen(cli_challenge) + 1);
	sprintf(tmp, "$NETNTLMv2$%s$%s$%s$%s", identity, srv_challenge, nethashv2, cli_challenge);
	MEM_FREE(identity);

	if (netntlmv2_valid(tmp, self)) {
		char *cp = str_alloc_copy(tmp);
		MEM_FREE(tmp);
		return cp;
	}
	MEM_FREE(tmp);
	return split_fields[1];
}

static char *netntlmv2_split(char *ciphertext, int index)
{
  static char out[TOTAL_LENGTH + 1];
  char *pos = NULL;
  int identity_length = 0;

  /* Calculate identity length */
  for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 11);

  memset(out, 0, TOTAL_LENGTH + 1);
  memcpy(&out, ciphertext, strlen(ciphertext));
  strlwr(&out[12 + identity_length]); /* Exclude: $NETNTLMv2$USERDOMAIN$ */

  return out;
}

static void *netntlmv2_get_binary(char *ciphertext)
{
  static uchar *binary;
  char *pos = NULL;
  int i, identity_length;

  if (!binary) binary = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

  for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);
  identity_length = pos - (ciphertext + 11);

  ciphertext += 11 + identity_length + 1 + SERVER_CHALL_LENGTH + 1;
  for (i=0; i<BINARY_SIZE; i++)
  {
    binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
    binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
  }

  return binary;
}

/* Calculate the NTLMv2 response for the given challenge, using the
   specified authentication identity (username and domain), password
   and client nonce.

   challenge: Identity length, Identity\0, Challenge Size, Server Challenge + Client Challenge
*/
static void netntlmv2_crypt_all(int count)
{
	int identity_length, challenge_size;
	int i = 0;

	/* --- HMAC #1 Calculations --- */
	identity_length = challenge[0];
	challenge_size = (*(challenge + 1 + identity_length + 1) << 8) | *(challenge + 1 + identity_length + 2);

#ifdef _OPENMP
#pragma omp parallel for
	for(i=0; i<count; i++)
#endif
	{
		unsigned char ntlm_v2_hash[16];
		HMACMD5Context ctx;

		if (!keys_prepared) {
			unsigned char ntlm[16];
			int len;

			/* Generate 16-byte NTLM hash */
			len = E_md4hash(saved_plain[i], saved_len[i], ntlm);

			// We do key setup of the next HMAC_MD5 here (once per salt)
			hmac_md5_init_K16(ntlm, &saved_ctx[i]);

			if (len <= 0)
				saved_plain[i][-len] = 0; // match truncation
		}

		/* HMAC-MD5(Username + Domain, NTLM Hash) */
		memcpy(&ctx, &saved_ctx[i], sizeof(ctx));
		hmac_md5_update((unsigned char *)&challenge[1], identity_length, &ctx);
		hmac_md5_final(ntlm_v2_hash, &ctx);

		/* --- Blob Construction --- */

		/*
		    The blob consists of the target (from Type 2 message), client nonce and timestamp.
		    This data was provided by the client during authentication and we can use it as is.
		*/

		/* --- HMAC #2 Caculations --- */

		/*
		  The (server) challenge from the Type 2 message is concatenated with the blob. The
		  HMAC-MD5 message authentication code algorithm is applied to this value using the
		  16-byte NTLMv2 hash (calculated above) as the key. This results in a 16-byte output
		  value.
		*/

		/*
		   Generate 16-byte non-client nonce portion of NTLMv2 Response
		   HMAC-MD5(Challenge + Nonce, NTLMv2 Hash)

		   The length of the challenge was set in netntlmv2_get_salt(). We find the server
		   challenge and blob following the identity and challenge size value.
		   challenge -> Identity length, Identity\0, Size (2 bytes), Server Challenge + Client Challenge (Blob)
		*/
		hmac_md5(ntlm_v2_hash, challenge + 1 + identity_length + 1 + 2, challenge_size, (unsigned char*)output[i]);
	}
	keys_prepared = 1;
}

static int netntlmv2_cmp_all(void *binary, int count)
{
	int index;
	for(index=0; index<count; index++)
		if (!memcmp(output[index], binary, BINARY_SIZE))
			return 1;
	return 0;
}

static int netntlmv2_cmp_one(void *binary, int index)
{
	return !memcmp(output[index], binary, BINARY_SIZE);
}

static int netntlmv2_cmp_exact(char *source, int index)
{
	return !memcmp(output[index], netntlmv2_get_binary(source), BINARY_SIZE);
}

/*
  We're essentially using three salts, but we're going to pack it into a single blob for now.

  Input:  $NETNTLMv2$USER_DOMAIN$_SERVER_CHALLENGE_$_NTLMv2_RESP_$_CLIENT_CHALLENGE_
    Username: <=20
    Domain: <=15
    Server Challenge: 8 bytes
    Client Challenge: ???
  Output: Identity length, Identity(UTF16)\0, Challenge Size, Server Challenge + Client Challenge
*/
static void *netntlmv2_get_salt(char *ciphertext)
{
  static unsigned char *binary_salt;
  int i, identity_length, challenge_size;
  char *pos = NULL;
#if !ARCH_ALLOWS_UNALIGNED
  static unsigned *bs2;
  if (!bs2) bs2 = mem_alloc_tiny(SALT_SIZE_MAX, MEM_ALIGN_WORD);
#endif

  if (!binary_salt) binary_salt = mem_alloc_tiny(SALT_SIZE_MAX, MEM_ALIGN_WORD);

  /* Calculate identity length */
  for (pos = ciphertext + 11; strncmp(pos, "$", 1) != 0; pos++);

  /* Convert identity (username + domain) string to NT unicode */
#if !ARCH_ALLOWS_UNALIGNED
  identity_length = enc_to_utf16((uint16 *)bs2, 2 * (USERNAME_LENGTH + DOMAIN_LENGTH), (uchar *)ciphertext + 11, pos - (ciphertext + 11)) * sizeof(int16);
  if (identity_length < 0) // Truncated at Unicode conversion.
	  identity_length = strlen16((UTF16 *)bs2) * sizeof(int16);
  memcpy(&binary_salt[1], bs2, identity_length);
#else
  identity_length = enc_to_utf16((uint16 *)&binary_salt[1], 2 * (USERNAME_LENGTH + DOMAIN_LENGTH), (uchar *)ciphertext + 11, pos - (ciphertext + 11)) * sizeof(int16);
  if (identity_length < 0) // Truncated at Unicode conversion.
	  identity_length = strlen16((UTF16 *)&binary_salt[1]) * sizeof(int16);
#endif

  /* Set server and client challenge size */

  /* Skip: $NETNTLMv2$USER_DOMAIN$ */
  ciphertext = pos + 1;

  /* SERVER_CHALLENGE$NTLMV2_RESPONSE$CLIENT_CHALLENGE --> SERVER_CHALLENGECLIENT_CHALLENGE */
  /* CIPHERTEXT == NTLMV2_RESPONSE (16 bytes / 32 characters) */
  challenge_size = (strlen(ciphertext) - CIPHERTEXT_LENGTH - 2) / 2;

  /* Store identity length */
  binary_salt[0] = identity_length;

  /* Set challenge size in response - 2 bytes */
  memset(binary_salt + 1 + identity_length, 0, 1);
  memset(binary_salt + 1 + identity_length + 1, (challenge_size & 0xFF00) >> 8, 1);
  memset(binary_salt + 1 + identity_length + 2, challenge_size & 0x00FF, 1);

  /* Set server challenge */
  for (i = 0; i < SERVER_CHALL_LENGTH / 2; i++)
    binary_salt[identity_length + 1 + 2 + 1 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  /* Set client challenge */
  ciphertext += SERVER_CHALL_LENGTH + 1 + CIPHERTEXT_LENGTH + 1;
  for (i = 0; i < strlen(ciphertext) / 2; ++i)
    binary_salt[identity_length + 1 + 2 + 1 + SERVER_CHALL_LENGTH / 2 + i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) + atoi16[ARCH_INDEX(ciphertext[i*2+1])];

  /* Return a concatenation of the server and client challenges and the identity value */
  return (void*)binary_salt;
}

static void netntlmv2_set_salt(void *salt)
{
	challenge = salt;
}

static void netntlmv2_set_key(char *key, int index)
{
	saved_len[index]= strlen(key);
	memcpy((char *)saved_plain[index], key, saved_len[index]+ 1);
	keys_prepared = 0;
}

static char *netntlmv2_get_key(int index)
{
	return (char *)saved_plain[index];
}

static int salt_hash(void *salt)
{
	// Hash the client challenge (in case server salt was spoofed)
	int identity_length = ((char *)salt)[0];
	return (*(ARCH_WORD_32 *)salt+1+identity_length+1+2+8) & (SALT_HASH_SIZE - 1);
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

struct fmt_main fmt_NETNTLMv2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE_MAX,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		netntlmv2_prepare,
		netntlmv2_valid,
		netntlmv2_split,
		netntlmv2_get_binary,
		netntlmv2_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		netntlmv2_set_salt,
		netntlmv2_set_key,
		netntlmv2_get_key,
		fmt_default_clear_keys,
		netntlmv2_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		netntlmv2_cmp_all,
		netntlmv2_cmp_one,
		netntlmv2_cmp_exact
	}
};
