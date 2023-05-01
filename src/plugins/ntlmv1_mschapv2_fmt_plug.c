/*
 * Previous files MSCHAPv2_fmt_plug.c and NETNTLM_fmt_plug.c now merged into
 * this one file, sharing functions.
 *
 * NETNTLM_fmt.c -- NTLM Challenge/Response
 * Written by JoMo-Kun <jmk at foofus.net> in 2007
 * and placed in the public domain.
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
 * MSCHAPv2_fmt.c -- Microsoft PPP CHAP Extensions, Version 2
 * Written by JoMo-Kun <jmk at foofus.net> in 2010
 * and placed in the public domain.
 *
 * Support for freeradius-wep-patch challenge/response format
 * added by Linus Lüssing in 2012 and is licensed under CC0/PD terms:
 * To the extent possible under law, Linus Lüssing has waived all copyright
 * and related or neighboring rights to this work. This work is published from:
 * Germany.
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
 * Modified for performance and support for SSE2, NTLMv1 ESS, OMP and UTF-8, by
 * magnum 2010-2011 and 2013.
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO

#if FMT_EXTERNS_H
extern struct fmt_main fmt_MSCHAPv2_new;
extern struct fmt_main fmt_NETNTLM_new;
#elif FMT_REGISTERS_H
john_register_one(&fmt_MSCHAPv2_new);
john_register_one(&fmt_NETNTLM_new);
#else

#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#include "simd-intrinsics.h"
#ifdef SIMD_COEF_32
#define NBKEYS                  (SIMD_COEF_32 * SIMD_PARA_MD4)
#else
#ifdef _OPENMP
#ifndef OMP_SCALE
#define OMP_SCALE               4
#endif
#include <omp.h>
#endif
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "memory.h"
#include "johnswap.h"
#include "sha.h"
#include "md4.h"
#include "md5.h"
#include "unicode.h"
#include "john.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define CHAP_FORMAT_LABEL       "MSCHAPv2"
#define CHAP_FORMAT_NAME        "C/R"
#define FORMAT_TAG              "$MSCHAPv2$"
#define FORMAT_TAG_LEN          (sizeof(FORMAT_TAG)-1)
#define FORMAT_TAGN             "$NETNTLM$"
#define FORMAT_TAGN_LEN         (sizeof(FORMAT_TAGN)-1)
#define CHAP_USERNAME_LENGTH    256
#define CHAP_CHALLENGE_LENGTH   64
#define CHAP_TOTAL_LENGTH       13 + CHAP_USERNAME_LENGTH + CHAP_CHALLENGE_LENGTH + CIPHERTEXT_LENGTH

#define NTLM_FORMAT_LABEL       "netntlm"
#define NTLM_FORMAT_NAME        "NTLMv1 C/R"
#define NTLM_TOTAL_LENGTH       (10 + 2 * 2 * SALT_SIZE + CIPHERTEXT_LENGTH)

#define ALGORITHM_NAME          "MD4 DES (ESS MD5) " MD4_ALGORITHM_NAME
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define FULL_BINARY_SIZE        (2 + 8 * 3)
#define BINARY_SIZE             (2 + 8)
#define BINARY_ALIGN            2
#define SALT_SIZE               8
#define SALT_ALIGN              MEM_ALIGN_WORD
#define CIPHERTEXT_LENGTH       48

#ifdef SIMD_COEF_32
#define PLAINTEXT_LENGTH        27
//#define SSE_OMP
#if defined (_OPENMP) && defined(SSE_OMP)
#define BLOCK_LOOPS             (2048 / NBKEYS)
#else
#define BLOCK_LOOPS             (1024 / NBKEYS)
#endif
#define MIN_KEYS_PER_CRYPT      (NBKEYS * BLOCK_LOOPS)
#define MAX_KEYS_PER_CRYPT      (NBKEYS * BLOCK_LOOPS)

// These 2 get the proper uint32_t limb from the SIMD mixed set. They both
// work properly for both BE and LE machines :) These SHOULD be used whenever
// the full uint32_t item is wanted, usually RHS of an assignment to uint32_t*
// NOTE, i is number is based on uint32_t[] and not uint8_t[] offsets.
#define GETOUTPOS_W32(i, index) ( (index&(SIMD_COEF_32-1))*4 + ((i<<2)&(0xffffffff-3))*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*4*SIMD_COEF_32*4 )
#define GETPOS_W32(i, index)    ( (index&(SIMD_COEF_32-1))*4 + ((i<<2)&(0xffffffff-3))*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32*4 )
// GETPOS HAS to be BE/LE specific
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32*4 )
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32*4 )
#endif
#else
#define PLAINTEXT_LENGTH        64
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      2048
#endif

#ifdef SIMD_COEF_32
static unsigned char *saved_key;
#else
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
#endif

static unsigned short (*crypt_key);
static unsigned char *nthash;
static uint32_t *bitmap;
static int cmps_per_crypt, use_bitmap;
static int valid_i, valid_j;

static uchar *challenge;
static int keys_prepared;
static struct fmt_main *my;

static char *chap_long_to_short(char *orig); /* used to cannonicalize the MSCHAPv2 format */

static struct fmt_tests chap_tests[] = {
	{"$MSCHAPv2$4c092fd3fd98236502e8591100046326$b912ce522524d33123a982cf330a57f8e953fa7974042b5d$6a4915d0ce61d42be533640a75391925$1111", "2222"},
	{"$MSCHAPv2$5B5D7C7D7B3F2F3E3C2C602132262628$82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF$21402324255E262A28295F2B3A337C7E$User", "clientPass"},
	{"$MSCHAPv2$d07054459a1fdbc266a006f0220e6fac$33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde$3545cb1d89b507a5de104435e81b14a4$testuser1", "Cricket8"},
	{"$MSCHAPv2$56d64cbe7bad61349a0b752335100eaf$d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b$7f8a466cff2a6bf0c80218bbf56d76bc$fred", "OMG!BBQ!11!one"}, /* domain\fred */
#if PLAINTEXT_LENGTH >= 35
	{"$MSCHAPv2$b3c42db475b881d3c52ff3923d7b3bf8$f07c7a4eb391f5debe32d814679a5a69661b86b33227c4f8$6321f8649b971bd11ce8d5cb22a4a738$bOb", "asdblahblahblahblahblahblahblahblah"}, /* WorkGroup\bOb */
#endif
	{"$MSCHAPv2$d94e7c7972b2376b28c268583e162de7$eba25a3b04d2c7085d01f842e2befc91745c40db0f792356$0677ca7318fd7f65ae1b4f58c9f4f400$lameuser", ""}, /* no password */
	{"$MSCHAPv2$8710da60ebfc4cab$c4e3bb55904c966927ee68e5f1472e1f5d8ec165713b5360$$foo4", "bar4" },
	{"$MSCHAPv2$8710da60ebfc4cab$c4e3bb55904c966927ee68e5f1472e1f5d8ec165713b5360$$", "bar4" },

	/* Ettercap generated three test vectors */
	{"$MSCHAPv2$3D79CC8CDC0261D4$B700770725F87739ADB110B310D9A289CDBB550ADCA6CB86$solar", "solarisalwaysbusy"},
	{"$MSCHAPv2$BA75EB14EFBFBF25$ED8CC90FD40FAA2D6BCD0ABD0B1F562FD777DF6C5609C98B$lulu", "password"},
	{"$MSCHAPv2$95A87FA62EBCD2E3C8B09E1B448A6C72$ED8CC90FD40FAA2D6BCD0ABD0B1F562FD777DF6C5609C98B$E2AE0995EAAC6CEFF0D9757428B51509$lulu", "password"},

	/* Single test vector from chapcrack's sample pcap file */
	{"$MSCHAPv2$6D0E1C056CD94D5F$1C93ABCE815400686BAECA315F348469256420598A73AD49$moxie", "bPCFyF2uL1p5Lg5yrKmqmY"},

	{"", "clientPass",     {"User",        "", "",    "5B5D7C7D7B3F2F3E3C2C602132262628", "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "21402324255E262A28295F2B3A337C7E"} },
	{"", "Cricket8",       {"testuser1",   "", "",    "d07054459a1fdbc266a006f0220e6fac", "33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde", "3545cb1d89b507a5de104435e81b14a4"} },
	{"", "OMG!BBQ!11!one", {"domain\\fred", "", "",   "56d64cbe7bad61349a0b752335100eaf", "d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b", "7f8a466cff2a6bf0c80218bbf56d76bc"} }, /* domain\fred */
	{"", "",               {"lameuser", "", "domain", "d94e7c7972b2376b28c268583e162de7", "eba25a3b04d2c7085d01f842e2befc91745c40db0f792356", "0677ca7318fd7f65ae1b4f58c9f4f400"} }, /* no password */
	{NULL}
};

static struct fmt_tests ntlm_tests[] = {
	{"$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "g3rg3g3rg3g3rg3"},
#ifndef SIMD_COEF_32 /* exceeds max length for SSE */
	{"$NETNTLM$1122334455667788$E463FAA5D868ECE20CAE622474A2F440A652D642156AF863", "M1xedC4se%^&*@)##(blahblah!@#"},
#endif
	{"$NETNTLM$c75c20bff9baa71f4765f360625700b0$81f5ecd8a77fe819f7f6689a08a27ac705fc2e1bb00cecb2", "password"},
	{"$NETNTLM$1122334455667788$35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A", "FooBarGerg"},
	{"$NETNTLM$1122334455667788$A4765EBFE83D345A7CB1660B8899251905164029F8086DDE", "visit www.foofus.net"},
	{"$NETNTLM$24ca92fdab441aa4c70e4fb229437ef3$abf7762caf2b1bbfc5cfc1f46665249f049e0af72ae5b5a9", "longpassword"},
	{"$NETNTLM$1122334455667788$B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233", "cory21"},
	{"", "g3rg3g3rg3g3rg3",               {"User", "", "", "lm-hash", "BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "1122334455667788"} },
	{"", "FooBarGerg",                    {"User", "", "", "lm-hash", "35B62750E1B9B3205C50D6BA351092C12A1B9B3CDC65D44A", "1122334455667788"} },
	{"", "visit www.foofus.net",          {"User", "", "", "lm-hash", "A4765EBFE83D345A7CB1660B8899251905164029F8086DDE", "1122334455667788"} },
	{"", "password",                      {"ESS", "", "", "4765f360625700b000000000000000000000000000000000", "81f5ecd8a77fe819f7f6689a08a27ac705fc2e1bb00cecb2", "c75c20bff9baa71f"} },
	{"", "cory21",                        {"User", "", "", "lm-hash", "B2B2220790F40C88BCFF347C652F67A7C4A70D3BEBD70233", "1122334455667788"} },
	{NULL}
};

inline static void setup_des_key(uchar key_56[], DES_key_schedule *ks)
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

static int chap_valid_long(char *ciphertext)
{
	char *pos, *pos2;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)!=0) return 0;

	if (strlen(ciphertext) > CHAP_TOTAL_LENGTH)
		return 0;

	/* Validate Authenticator/Server Challenge Length */
	pos = &ciphertext[FORMAT_TAG_LEN];
	for (pos2 = pos; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHAP_CHALLENGE_LENGTH / 2)) )
		return 0;

	/* Validate MSCHAPv2 Response Length */
	pos2++; pos = pos2;
	for (; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
		return 0;

	/* Validate Peer/Client Challenge Length */
	pos2++; pos = pos2;
	for (; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHAP_CHALLENGE_LENGTH / 2)) )
		return 0;

	/* Validate Username Length */
	if (strlen(++pos2) > CHAP_USERNAME_LENGTH)
		return 0;

	return 1;
}

static int chap_valid_short(char *ciphertext)
{
	char *pos, *pos2;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)!=0) return 0;

	if (strlen(ciphertext) > CHAP_TOTAL_LENGTH)
		return 0;

	/* Validate MSCHAPv2 Challenge Length */
	pos = &ciphertext[FORMAT_TAG_LEN];
	for (pos2 = pos; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHAP_CHALLENGE_LENGTH / 4)) )
		return 0;

	/* Validate MSCHAPv2 Response Length */
	pos2++; pos = pos2;
	for (; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CIPHERTEXT_LENGTH)) )
		return 0;

	return 1;
}

static void chap_get_challenge(const char *ciphertext,
                               unsigned char *binary_salt)
{
	int i;
	const char *pos = ciphertext + FORMAT_TAG_LEN;

	for (i = 0; i < SALT_SIZE; i++)
		binary_salt[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) +
			atoi16[ARCH_INDEX(pos[i*2+1])];
}

/* Either the cipherext already contains the MSCHAPv2 Challenge (4 Bytes) or
   we are going to calculate it via:
   sha1(|Peer/Client Challenge (8 Bytes)|Authenticator/Server Challenge (8 Bytes)|Username (<=256)|)

   NOTE, we now ONLY call this function the the short form. The long form gets converted into the short
   form in either prepare or split function.  The short form is cannonical form (Change made July, 2014, JimF)
*/
static void *chap_get_salt(char *ciphertext)
{
	static unsigned char *binary_salt;
	unsigned char digest[20];

	if (!binary_salt)
		binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	/* This is just to silence scan-build. It will never happen.
	   It is unclear why only this format gave warnings, many others do
	   similar things. */
	if (!ciphertext)
		return ciphertext;

	memset(binary_salt, 0, SALT_SIZE);
	memset(digest, 0, 20);

	chap_get_challenge(ciphertext, binary_salt);
	return (void*)binary_salt;
}

/*
 * This function will convert long hashes, into short ones (the short is now cannonical format)
 * converts
 *   $MSCHAPv2$95a87fa62ebcd2e3c8b09e1b448a6c72$ed8cc90fd40faa2d6bcd0abd0b1f562fd777df6c5609c98b$e2ae0995eaac6ceff0d9757428b51509$lulu
 * into
 *   $MSCHAPv2$ba75eb14efbfbf25$ed8cc90fd40faa2d6bcd0abd0b1f562fd777df6c5609c98b$$
 *
 * This code was moved from get_salt().
 */
static char *chap_long_to_short(char *ciphertext) {
	static char Buf[CHAP_TOTAL_LENGTH+1];	// larger than we need, but not a big deal
	static SHA_CTX ctx;
	unsigned char tmp[16];
	unsigned char digest[20];
	char *pos = NULL;
	int i;
	SHA1_Init(&ctx);

	/* Peer Challenge */
	pos = ciphertext + FORMAT_TAG_LEN + 16*2 + 1 + 24*2 + 1; /* Skip $MSCHAPv2$, Authenticator Challenge and Response Hash */

	memset(tmp, 0, 16);
	for (i = 0; i < 16; i++)
		tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

	SHA1_Update(&ctx, tmp, 16);

	/* Authenticator Challenge */
	pos = ciphertext + FORMAT_TAG_LEN; /* Skip $MSCHAPv2$ */

	memset(tmp, 0, 16);
	for (i = 0; i < 16; i++)
		tmp[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

	SHA1_Update(&ctx, tmp, 16);

	/* Username - Only the user name (as presented by the peer and
	   excluding any prepended domain name) is used as input to SHAUpdate()
	*/
	pos = ciphertext + FORMAT_TAG_LEN + 16*2 + 1 + 24*2 + 1 + 16*2 + 1; /* Skip $MSCHAPv2$, Authenticator, Response and Peer */
	SHA1_Update(&ctx, pos, strlen(pos));

	SHA1_Final(digest, &ctx);

	// Ok, now we re-make our ciphertext buffer, into the short cannonical form.
	strcpy(Buf, FORMAT_TAG);
	pos = Buf + FORMAT_TAG_LEN;
	for (i = 0; i < SALT_SIZE; i++) {
		//binary_salt.u8[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];
		pos[(i<<1)] = itoa16[digest[i]>>4];
		pos[(i<<1)+1] = itoa16[digest[i]&0xF];
	}
	memcpy(&pos[16], &ciphertext[42], CIPHERTEXT_LENGTH+2);
	pos[16+CIPHERTEXT_LENGTH+2] = '$';
	pos[16+CIPHERTEXT_LENGTH+3] = 0;
	//printf("short=%s  original=%s\n", Buf, ciphertext);
	return Buf;
}

static int chap_valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *cp = NULL;

	if (chap_valid_short(ciphertext))
		cp = ciphertext + FORMAT_TAG_LEN + CHAP_CHALLENGE_LENGTH / 4 + 1;
	else if (chap_valid_long(ciphertext))
		cp = ciphertext + FORMAT_TAG_LEN + CHAP_CHALLENGE_LENGTH / 2 + 1;

	if (cp) {
		uchar key[7] = {0, 0, 0, 0, 0, 0, 0};
		DES_key_schedule ks;
		DES_cblock b3cmp;
		uchar binary[8];
		DES_cblock *challenge = chap_get_salt(ciphertext);
		int i, j;

		cp += 2 * 8 * 2;

		for (i = 0; i < 8; i++) {
			binary[i] = atoi16[ARCH_INDEX(cp[i * 2])] << 4;
			binary[i] |= atoi16[ARCH_INDEX(cp[i * 2 + 1])];
		}

		key[0] = valid_i; key[1] = valid_j;
		setup_des_key(key, &ks);
		DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
		if (!memcmp(binary, &b3cmp, 8))
			return 1;

		for (i = 0; i < 0x100; i++)
		for (j = 0; j < 0x100; j++) {
			key[0] = i; key[1] = j;
			setup_des_key(key, &ks);
			DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
			if (!memcmp(binary, &b3cmp, 8)) {
				valid_i = i;
				valid_j = j;
				return 1;
			}
		}
#ifdef DEBUG
		if (!bench_or_test_running)
			fprintf(stderr, "Rejected MSCHAPv2 hash with "
			        "invalid 3rd block\n");
#endif
	}
	return 0;
}

static char *chap_prepare_long(char *split_fields[10])
{
	char *username, *cp;

	/* DOMAIN\USERNAME -or - USERNAME -- ignore DOMAIN */
	if ((username = strstr(split_fields[0], "\\")) == NULL)
		username = split_fields[0];
	else
		username++;

	cp = mem_alloc(FORMAT_TAG_LEN+strlen(split_fields[3])+1+strlen(split_fields[4])+
	               1+strlen(split_fields[5])+1+strlen(username)+1);
	sprintf(cp, "%s%s$%s$%s$%s", FORMAT_TAG, split_fields[3], split_fields[4],
	        split_fields[5], username);
	if (chap_valid_long(cp)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *chap_prepare_short(char *split_fields[10])
{
	char *cp;

	cp = mem_alloc(FORMAT_TAG_LEN+strlen(split_fields[3])+1+strlen(split_fields[4])+
	               1+1+1);
	sprintf(cp, "%s%s$%s$$", FORMAT_TAG, split_fields[3], split_fields[4]);
	if (chap_valid_short(cp)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *chap_prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	char *ret;

	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN)) {
		// check for a short format that has any extra trash fields, and if so remove them.
		char *cp1, *cp2, *cp3;
		static char *out;
		if (!out)
			out = mem_alloc_tiny(FORMAT_TAG_LEN + CHAP_CHALLENGE_LENGTH/4 + 1 + CIPHERTEXT_LENGTH + 3, MEM_ALIGN_NONE);
		cp1 = split_fields[1];
		cp1 += FORMAT_TAG_LEN;
		cp2 = strchr(cp1, '$');
		ret = NULL;
		if (cp2 && cp2-cp1 == CHAP_CHALLENGE_LENGTH/4) {
			++cp2;
			cp3 = strchr(cp2, '$');
			if (cp3 && cp3-cp2 == CIPHERTEXT_LENGTH && (strlen(cp3) > 2 || cp3[1] != '$')) {
				ret = out;
				memcpy(ret, split_fields[1], cp3-split_fields[1] + 1);
				ret[(cp3-split_fields[1]) + 1] = '$';
				ret[(cp3-split_fields[1]) + 2] = 0;
				//printf("Here is the cut item: %s\n", ret);
			}
		}
	}
	else if (split_fields[0] && split_fields[3] && split_fields[4] &&
	         split_fields[5] &&
	         strlen(split_fields[3]) == CHAP_CHALLENGE_LENGTH/2 &&
	         strlen(split_fields[4]) == CIPHERTEXT_LENGTH &&
	         strlen(split_fields[5]) == CHAP_CHALLENGE_LENGTH/2)
		ret = chap_prepare_long(split_fields);
	else if (split_fields[0] && split_fields[3] && split_fields[4] &&
	         strlen(split_fields[3]) == CHAP_CHALLENGE_LENGTH/4 &&
	         strlen(split_fields[4]) == CIPHERTEXT_LENGTH)
		ret = chap_prepare_short(split_fields);
	else
		ret = NULL;

	if (ret && chap_valid_long(ret))
		ret = chap_long_to_short(ret);
	else if (chap_valid_long(split_fields[1]))
		ret = chap_long_to_short(split_fields[1]);

	return ret ? ret : split_fields[1];
}

static char *chap_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CHAP_TOTAL_LENGTH + 1];
	int i, j = 0;

	memset(out, 0, CHAP_TOTAL_LENGTH + 1);
	memcpy(out, ciphertext, strlen(ciphertext));

	/* convert hashes to lower-case - exclude $MSCHAPv2 and USERNAME */
	for (i = FORMAT_TAG_LEN; i < CHAP_TOTAL_LENGTH + 1 && j < 3; i++) {
		if (out[i] >= 'A' && out[i] <= 'Z')
			out[i] |= 0x20;
		else if (out[i] == '$')
			j++;
	}

	if (chap_valid_long(out))
		return chap_long_to_short(out);

	return out;
}

static void *ntlm_get_salt(char *ciphertext)
{
	static uchar *binary_salt;
	int i;

	if (!binary_salt)
		binary_salt = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	if (ciphertext[25] == '$') {
		// Server challenge
		ciphertext += FORMAT_TAGN_LEN;
		for (i = 0; i < SALT_SIZE; ++i)
		   binary_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) +
			   atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	} else {
		uchar es_salt[2*SALT_SIZE], k1[2*SALT_SIZE];
		MD5_CTX ctx;

		ciphertext += FORMAT_TAGN_LEN;
		// Extended Session Security,
		// Concatenate Server & Client challenges
		for (i = 0;i < 2 * SALT_SIZE; ++i)
		   es_salt[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])] << 4) +
			   atoi16[ARCH_INDEX(ciphertext[i*2+1])];

		// MD5 the concatenated challenges, result is our key
		MD5_Init(&ctx);
		MD5_Update(&ctx, es_salt, 16);
		MD5_Final((void*)k1, &ctx);
		memcpy(binary_salt, k1, SALT_SIZE); // but only 8 bytes of it
	}
	return (void*)binary_salt;
}

static int ntlm_valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	if (strncmp(ciphertext, FORMAT_TAGN, FORMAT_TAGN_LEN)!=0) return 0;

	if ((strlen(ciphertext) != 74) && (strlen(ciphertext) != 90)) return 0;

	if ((ciphertext[25] != '$') && (ciphertext[41] != '$')) return 0;

	for (pos = &ciphertext[FORMAT_TAGN_LEN]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos != '$') return 0;

	for (pos++; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (!*pos && ((pos - ciphertext - 26 == CIPHERTEXT_LENGTH) ||
	              (pos - ciphertext - 42 == CIPHERTEXT_LENGTH))) {
		uchar key[7] = {0, 0, 0, 0, 0, 0, 0};
		DES_key_schedule ks;
		DES_cblock b3cmp;
		uchar binary[8];
		DES_cblock *challenge = ntlm_get_salt(ciphertext);
		int i, j;

		ciphertext = strrchr(ciphertext, '$') + 1 + 2 * 8 * 2;
		for (i = 0; i < 8; i++) {
			binary[i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] << 4;
			binary[i] |= atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
		}

		key[0] = valid_i; key[1] = valid_j;
		setup_des_key(key, &ks);
		DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
		if (!memcmp(binary, &b3cmp, 8))
			return 1;

		for (i = 0; i < 0x100; i++)
		for (j = 0; j < 0x100; j++) {
			key[0] = i; key[1] = j;
			setup_des_key(key, &ks);
			DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
			if (!memcmp(binary, &b3cmp, 8)) {
				valid_i = i;
				valid_j = j;
				return 1;
			}
		}
#ifdef DEBUG
		if (!bench_or_test_running)
			fprintf(stderr, "Rejected NetNTLM hash with invalid "
			        "3rd block\n");
#endif
	}
	return 0;
}

static char *ntlm_prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	char clientChal[17];

	if (!strncmp(split_fields[1], FORMAT_TAGN, FORMAT_TAGN_LEN))
		return split_fields[1];
	if (!split_fields[3]||!split_fields[4]||!split_fields[5])
		return split_fields[1];

	if (strlen(split_fields[4]) != CIPHERTEXT_LENGTH)
		return split_fields[1];

	// this string suggests we have an improperly formatted NTLMv2
	if (!strncmp(&split_fields[4][32], "0101000000000000", 16))
		return split_fields[1];

	// Ignore anonymous login (Username "", Password "")
	if (split_fields[0] && strlen(split_fields[0]) == 0 &&
	    !strncasecmp(split_fields[3], "edb7398877d716be", 16) &&
	    !strncasecmp(split_fields[4], "42aeb71fbb6dc18499016b08"
	                 "b178ba65430ad39ae2498629", 48))
		return split_fields[1];

	// Handle ESS (8 byte client challenge in "LM" field padded with zeros)
	if (strlen(split_fields[3]) == 48 &&
	    !strncmp(&split_fields[3][16], "00000000000000000000000000000000",
	             32))
	{
		memcpy(clientChal, split_fields[3],16);
		clientChal[16] = 0;
	}
	else
		clientChal[0] = 0;
	cp = mem_alloc(FORMAT_TAGN_LEN+strlen(split_fields[5])+strlen(clientChal)+1+
	               strlen(split_fields[4])+1);
	sprintf(cp, "%s%s%s$%s", FORMAT_TAGN, split_fields[5], clientChal,
	        split_fields[4]);

	if (ntlm_valid(cp,self)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *ntlm_split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[NTLM_TOTAL_LENGTH + 1];

	memset(out, 0, NTLM_TOTAL_LENGTH + 1);
	strcpy(out, ciphertext);
	strlwr(&out[FORMAT_TAGN_LEN]); /* Exclude: $NETNTLM$ */

	return out;
}

static void set_salt(void *salt)
{
	challenge = salt;
}

// ISO-8859-1 to UCS-2, directly into vector key buffer
static void set_key_ansi(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const uchar *key = (uchar*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS_W32(0, index)];
	unsigned int len, temp2;

	len = 0;
	while((temp2 = *key++)) {
		unsigned int temp;
		if ((temp = *key++) && len < PLAINTEXT_LENGTH - 1)
		{
			temp2 |= (temp << 16);
			*keybuf_word = temp2;
		}
		else
		{
			temp2 |= (0x80 << 16);
			*keybuf_word = temp2;
			len++;
			goto key_cleaning;
		}
		len += 2;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	((unsigned int*)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) +
	                           (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32] = len << 4;
#else
#if ARCH_LITTLE_ENDIAN
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = saved_key[index];
	while (*s)
		*d++ = *s++;
	*d = 0;
	saved_len[index] = (int)((char*)d - (char*)saved_key[index]);
#else
	UTF8 *s = (UTF8*)_key;
	UTF8 *d = (UTF8*)saved_key[index];
	while (*s) {
		*d++ = *s++;
		++d;
	}
	*d = 0;
	saved_len[index] = (int)((char*)d - (char*)saved_key[index]);
#endif
#endif
	keys_prepared = 0;
}

// Legacy codepage to UCS-2, directly into vector key buffer
static void set_key_CP(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const uchar *key = (uchar*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS_W32(0, index)];
	unsigned int len, temp2;

	len = 0;
	while((temp2 = *key++)) {
		unsigned int temp;
		temp2 = CP_to_Unicode[temp2];
		if ((temp = *key++) && len < PLAINTEXT_LENGTH - 1)
		{
			temp = CP_to_Unicode[temp];
			temp2 |= (temp << 16);
			*keybuf_word = temp2;
		} else {
			temp2 |= (0x80 << 16);
			*keybuf_word = temp2;
			len++;
			goto key_cleaning_enc;
		}
		len += 2;
		keybuf_word += SIMD_COEF_32;
	}
	*keybuf_word = 0x80;

key_cleaning_enc:
	keybuf_word += SIMD_COEF_32;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	((unsigned int*)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) +
	                           (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32] = len << 4;
#else
	saved_len[index] = enc_to_utf16(saved_key[index],
	                                       PLAINTEXT_LENGTH + 1,
	                                       (uchar*)_key,
	                                       strlen(_key)) << 1;
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
#endif
	keys_prepared = 0;
}

// UTF-8 to UCS-2, directly into vector key buffer
static void set_key_utf8(char *_key, int index)
{
#ifdef SIMD_COEF_32
	const UTF8 *source = (UTF8*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS_W32(0, index)];
	UTF32 chl, chh = 0x80;
	unsigned int len = 0;

	while (*source) {
		chl = *source;
		if (chl >= 0xC0) {
			unsigned int extraBytesToRead;

			extraBytesToRead = opt_trailingBytesUTF8[chl & 0x3f];
			switch (extraBytesToRead) {
#if NT_FULL_UNICODE
			case 3:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					goto bailout;
#endif
			case 2:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					goto bailout;
			case 1:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					goto bailout;
			case 0:
				break;
			default:
				goto bailout;
			}
			chl -= offsetsFromUTF8[extraBytesToRead];
		}
		source++;
		len++;
#if NT_FULL_UNICODE
		if (chl > UNI_MAX_BMP) {
			if (len == PLAINTEXT_LENGTH) {
				chh = 0x80;
				*keybuf_word = (chh << 16) | chl;
				keybuf_word += SIMD_COEF_32;
				break;
			}
			#define halfBase 0x0010000UL
			#define halfShift 10
			#define halfMask 0x3FFUL
			#define UNI_SUR_HIGH_START  (UTF32)0xD800
			#define UNI_SUR_LOW_START   (UTF32)0xDC00
			chl -= halfBase;
			chh = (UTF16)((chl & halfMask) + UNI_SUR_LOW_START);;
			chl = (UTF16)((chl >> halfShift) + UNI_SUR_HIGH_START);
			len++;
		} else
#endif
		if (*source && len < PLAINTEXT_LENGTH) {
			chh = *source;
			if (chh >= 0xC0) {
				unsigned int extraBytesToRead =
					opt_trailingBytesUTF8[chh & 0x3f];
				switch (extraBytesToRead) {
#if NT_FULL_UNICODE
				case 3:
					++source;
					if (*source) {
						chl <<= 6;
						chl += *source;
					} else
						goto bailout;
#endif
				case 2:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						goto bailout;
				case 1:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						goto bailout;
				case 0:
					break;
				default:
					goto bailout;
				}
				chh -= offsetsFromUTF8[extraBytesToRead];
			}
			source++;
			len++;
		} else {
			chh = 0x80;
			*keybuf_word = (chh << 16) | chl;
			keybuf_word += SIMD_COEF_32;
			break;
		}
		*keybuf_word = (chh << 16) | chl;
		keybuf_word += SIMD_COEF_32;
	}
	if (chh != 0x80 || len == 0) {
		*keybuf_word = 0x80;
		keybuf_word += SIMD_COEF_32;
	}

bailout:
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += SIMD_COEF_32;
	}
	((unsigned int*)saved_key)[14*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) +
	                           (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32] = len << 4;
#else
	saved_len[index] = utf8_to_utf16(saved_key[index],
	                                        PLAINTEXT_LENGTH + 1,
	                                        (uchar*)_key,
	                                        strlen(_key)) << 1;
	if (saved_len[index] < 0)
		saved_len[index] = strlen16(saved_key[index]);
#endif
	keys_prepared = 0;
}

static void init(struct fmt_main *self)
{
#if defined (_OPENMP) && !defined(SIMD_COEF_32)
	omp_autotune(self, OMP_SCALE);
#endif
	my = self;
	if (options.target_enc == UTF_8) {
		self->methods.set_key = set_key_utf8;
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
	} else {
		if (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)
			self->methods.set_key = set_key_CP;
	}
	if (!saved_key) {
#if SIMD_COEF_32
		saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
		                             sizeof(*saved_key) * 64, MEM_ALIGN_SIMD);
		nthash    = mem_calloc_align(self->params.max_keys_per_crypt,
		                             sizeof(*nthash) * 16, MEM_ALIGN_SIMD);
#else
		saved_key = mem_calloc(self->params.max_keys_per_crypt,
		                       sizeof(*saved_key));
		nthash    = mem_calloc(self->params.max_keys_per_crypt,
		                       sizeof(*nthash) * 16);
		saved_len = mem_calloc(self->params.max_keys_per_crypt,
		                       sizeof(*saved_len));
#endif
		crypt_key = mem_calloc(self->params.max_keys_per_crypt,
		                       sizeof(unsigned short));
	}
	if (bitmap == NULL)
		bitmap = mem_calloc_align(1, 0x10000 / 8, MEM_ALIGN_CACHE);
	else
		memset(bitmap, 0, 0x10000 / 8);
	use_bitmap = 0; /* we did not use bitmap yet */
	cmps_per_crypt = 2; /* try bitmap */
}

static void done(void)
{
	MEM_FREE(bitmap);
	MEM_FREE(crypt_key);
	MEM_FREE(nthash);
#ifndef SIMD_COEF_32
	MEM_FREE(saved_len);
#endif
	MEM_FREE(saved_key);
}

// Get the key back from the key buffer, from UCS-2
static char *get_key(int index)
{
#ifdef SIMD_COEF_32
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS_W32(0, index)];
	static UTF16 key[PLAINTEXT_LENGTH + 1];
	unsigned int md4_size=0;
	unsigned int i=0;

	for (; md4_size < PLAINTEXT_LENGTH; i += SIMD_COEF_32, md4_size++)
	{
#if ARCH_LITTLE_ENDIAN==1
		key[md4_size] = keybuf_word[i];
		key[md4_size+1] = keybuf_word[i] >> 16;
		if (key[md4_size] == 0x80 && key[md4_size+1] == 0) {
			key[md4_size] = 0;
			break;
		}
		++md4_size;
		if (key[md4_size] == 0x80 &&
		    ((keybuf_word[i+SIMD_COEF_32]&0xFFFF) == 0 ||
		     md4_size == PLAINTEXT_LENGTH))
		{
			key[md4_size] = 0;
			break;
		}
#else
		unsigned int INWORD = JOHNSWAP(keybuf_word[i]);
		key[md4_size] = INWORD >> 16;
		key[md4_size+1] = INWORD;
		if (key[md4_size] == 0x8000 && key[md4_size+1] == 0) {
			key[md4_size] = 0;
			break;
		}
		++md4_size;
		if (key[md4_size] == 0x8000 && (md4_size == PLAINTEXT_LENGTH ||
		    (keybuf_word[i+SIMD_COEF_32]&0xFFFF0000) == 0))
		{
			key[md4_size] = 0;
			break;
		}
#endif
	}
	return (char*)utf16_to_enc(key);
#else
	return (char*)utf16_to_enc(saved_key[index]);
#endif
}

static void *get_binary(char *ciphertext)
{
	static uchar *binary;
	static int warned = 0, loaded = 0;
	DES_cblock *challenge = my->methods.salt(ciphertext);
	int i, j;

	if (!binary) binary = mem_alloc_tiny(FULL_BINARY_SIZE, BINARY_ALIGN);

	if (john_main_process)
	if (!warned && !ldr_in_pot && !bench_or_test_running && ++loaded > 100) {
		warned = 1;
		fprintf(stderr, "%s: Note: slow loading. For short runs, try "
		        "--format=%s-naive\ninstead. That version loads "
		        "faster but runs slower.\n", my->params.label,
		        my->params.label);
	}

	if (chap_valid_short(ciphertext))
		ciphertext += FORMAT_TAG_LEN + CHAP_CHALLENGE_LENGTH / 4 + 1;
	else if (chap_valid_long(ciphertext))
		ciphertext += FORMAT_TAG_LEN + CHAP_CHALLENGE_LENGTH / 2 + 1;
	else /* ntlmv1 */
		ciphertext = strrchr(ciphertext, '$') + 1;

	for (i = 0; i < FULL_BINARY_SIZE - 2; i++) {
		binary[2 + i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] << 4;
		binary[2 + i] |= atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}

	{
		uchar key[7] = {0, 0, 0, 0, 0, 0, 0};
		DES_key_schedule ks;
		DES_cblock b3cmp;

		key[0] = valid_i; key[1] = valid_j;
		setup_des_key(key, &ks);
		DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
		if (!memcmp(&binary[2 + 8 * 2], &b3cmp, 8)) {
			binary[0] = valid_i; binary[1] = valid_j;
			goto out;
		}

		for (i = 0; i < 0x100; i++)
		for (j = 0; j < 0x100; j++) {
			key[0] = i; key[1] = j;
			setup_des_key(key, &ks);
			DES_ecb_encrypt(challenge, &b3cmp, &ks, DES_ENCRYPT);
			if (!memcmp(&binary[2 + 8 * 2], &b3cmp, 8)) {
				binary[0] = i; binary[1] = j;
				goto out;
			}
		}
		fprintf(stderr, "Bug: %s hash with invalid 3rd block, should "
		        "have been rejected in valid()\n", my->params.label);
		binary[0] = binary[1] = 0x55;
	}

out:
	return binary;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;

	if (!keys_prepared) {
		int i = 0;

		if (use_bitmap) {
#if MAX_KEYS_PER_CRYPT >= 200
//#warning Notice: Using memset
			memset(bitmap, 0, 0x10000 / 8);
#else
//#warning Notice: Not using memset
#ifdef SIMD_COEF_32
			for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++)
#else
			for (i = 0; i < count; i++)
#endif
			{
				unsigned int value = crypt_key[i];
				bitmap[value >> 5] = 0;
			}
#endif
		}

		use_bitmap = cmps_per_crypt >= 2;
		cmps_per_crypt = 0;

#ifdef SIMD_COEF_32
#if (BLOCK_LOOPS > 1)
#if defined(_OPENMP) && defined(SSE_OMP)
#pragma omp parallel for
#endif
		for (i = 0; i < BLOCK_LOOPS; i++)
			SIMDmd4body(&saved_key[i * NBKEYS * 64], (unsigned int*)&nthash[i * NBKEYS * 16], NULL, SSEi_MIXED_IN);
#else
		SIMDmd4body(saved_key, (unsigned int*)nthash, NULL, SSEi_MIXED_IN);
#endif
		if (use_bitmap)
			for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++) {
				unsigned int value;

				value = *(uint32_t*)
					&nthash[GETOUTPOS_W32(3, i)] >> 16;
				crypt_key[i] = value;
#if defined(_OPENMP) && defined(SSE_OMP)
#pragma omp atomic
#endif
				bitmap[value >> 5] |= 1U << (value & 0x1f);
			}
		else
			for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++) {
				crypt_key[i] = *(uint32_t*)
					&nthash[GETOUTPOS_W32(3, i)] >> 16;
			}
#else
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (i = 0; i < count; i++) {
			MD4_CTX ctx;

			MD4_Init( &ctx );
			MD4_Update(&ctx, saved_key[i], saved_len[i]);
			MD4_Final((uchar*)&nthash[i * 16], &ctx);

			crypt_key[i] = ((unsigned short*)&nthash[i * 16])[7];
			if (use_bitmap) {
				unsigned int value = crypt_key[i];
#ifdef _OPENMP
#pragma omp atomic
#endif
				bitmap[value >> 5] |= 1U << (value & 0x1f);
			}
		}
#endif
		keys_prepared = 1;
	}
	return count;
}

static int cmp_one(void *binary, int index)
{
#if ARCH_LITTLE_ENDIAN==1 || !defined(SIMD_COEF_32)
	if (crypt_key[index] == *(unsigned short*)binary)
#else
	if ( JOHNSWAP(crypt_key[index])>>16 == *(unsigned short*)binary)
#endif
	{
		DES_key_schedule ks;
		DES_cblock computed_binary;
		unsigned int key[2];
#ifdef SIMD_COEF_32
		int i;

		for (i = 0; i < 2; i++)
			key[i] =
#if ARCH_LITTLE_ENDIAN==1
				*(uint32_t*) &nthash[GETOUTPOS_W32(i, index)];
#else
				JOHNSWAP (*(uint32_t*) &nthash[GETOUTPOS_W32(i, index)]);
#endif
#else
		memcpy(key, &nthash[index * 16], 8);
#endif
		setup_des_key((unsigned char*)key, &ks);
		DES_ecb_encrypt((DES_cblock*)challenge, &computed_binary,
		                &ks, DES_ENCRYPT);
		return !memcmp(((char*)binary) + 2, computed_binary, 8);
	}

	return 0;
}

static int cmp_all(void *binary, int count)
{
#if ARCH_LITTLE_ENDIAN==1 || !defined(SIMD_COEF_32)
	unsigned int value = *(unsigned short*)binary;
#else
	unsigned int value = JOHNSWAP(*(unsigned short*)binary)>>16;
#endif
	int index;

	cmps_per_crypt++;

	if (use_bitmap && !(bitmap[value >> 5] & (1U << (value & 0x1f))))
		goto out;

#ifdef SIMD_COEF_32
	/* Let's give the optimizer a hint! */
	for (index = 0; index < NBKEYS * BLOCK_LOOPS; index += 2)
#else
	for (index = 0; index < count; index += 2)
#endif
	{
		unsigned int a = crypt_key[index];
		unsigned int b = crypt_key[index + 1];

		if (a == value || b == value)
			goto thorough;
	}

	goto out;

thorough:
#ifdef SIMD_COEF_32
	for (index = 0; index < NBKEYS * BLOCK_LOOPS; index++)
#else
	for (; index < count; index++)
#endif
	{
		if (crypt_key[index] == value && cmp_one(binary, index))
			return 1;
	}

out:
	return 0;
}

static int cmp_exact(char *source, int index)
{
	DES_key_schedule ks;
	uchar binary[24];
	union {
		unsigned char key[24];
		unsigned int Key32[6];
	}k;
	char *cp;
	int i;

#ifdef SIMD_COEF_32
	for (i = 0; i < 4; i++)
		k.Key32[i] =
#if ARCH_LITTLE_ENDIAN==1
			*(uint32_t*)&nthash[GETOUTPOS_W32(i, index)];
#else
			JOHNSWAP(*(uint32_t*)&nthash[GETOUTPOS_W32(i, index)]);
#endif
#else
	memcpy(k.key, &nthash[index * 16], 16);
#endif
	/* Hash is NULL padded to 21-bytes */
	memset(&k.key[16], 0, 5);

	/* Split into three 7-byte segments for use as DES keys
	   Use each key to DES encrypt challenge
	   Concatenate output to for 24-byte NTLM response */
	setup_des_key(k.key, &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)binary,
	                &ks, DES_ENCRYPT);
	setup_des_key(&k.key[7], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[8],
	                &ks, DES_ENCRYPT);
	setup_des_key(&k.key[14], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[16],
	                &ks, DES_ENCRYPT);

	// With the normalized source we simply need to skip the
	// $MSCHAPv2$hhhhhhhhhhhhhhhh$ string to get 'real' binary data.
	// $NETNTLM$c75c20bff9baa71f4765f360625700b0$
	cp = &source[11];
	cp = strchr(cp, '$');
	++cp;
	for (i = 0; i < 24; ++i) {
		unsigned char c = (atoi16[ARCH_INDEX(*cp)] << 4) +
		                  (atoi16[ARCH_INDEX(*(cp+1))] );
		if (c != binary[i])
			return 0;
		cp += 2;
	}
	return 1;
}

static int salt_hash(void *salt) { return *(uint32_t*)salt & (SALT_HASH_SIZE - 1); }

#if ARCH_LITTLE_ENDIAN==1 || !defined(SIMD_COEF_32)
static int binary_hash_0(void *binary) { return *(unsigned short*)binary & PH_MASK_0; }
static int binary_hash_1(void *binary) { return *(unsigned short*)binary & PH_MASK_1; }
static int binary_hash_2(void *binary) { return *(unsigned short*)binary & PH_MASK_2; }
static int binary_hash_3(void *binary) { return *(unsigned short*)binary & PH_MASK_3; }
#else
static int binary_hash_0(void *binary) { return (JOHNSWAP(*(unsigned short*)binary)>>16) & PH_MASK_0; }
static int binary_hash_1(void *binary) { return (JOHNSWAP(*(unsigned short*)binary)>>16) & PH_MASK_1; }
static int binary_hash_2(void *binary) { return (JOHNSWAP(*(unsigned short*)binary)>>16) & PH_MASK_2; }
static int binary_hash_3(void *binary) { return (JOHNSWAP(*(unsigned short*)binary)>>16) & PH_MASK_3; }
#endif

static int get_hash_0(int index) { return crypt_key[index] & PH_MASK_0; }
static int get_hash_1(int index) { return crypt_key[index] & PH_MASK_1; }
static int get_hash_2(int index) { return crypt_key[index] & PH_MASK_2; }
static int get_hash_3(int index) { return crypt_key[index] & PH_MASK_3; }

struct fmt_main fmt_MSCHAPv2_new = {
	{
		CHAP_FORMAT_LABEL,
		CHAP_FORMAT_NAME,
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
#if !defined(SIMD_COEF_32) || (defined(SIMD_COEF_32) && defined(SSE_OMP))
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAG },
		chap_tests
	}, {
		init,
		done,
		fmt_default_reset,
		chap_prepare,
		chap_valid,
		chap_split,
		get_binary,
		chap_get_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			NULL,
			NULL,
			NULL
		},
		salt_hash,
		NULL,
		set_salt,
		set_key_ansi,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			NULL,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_NETNTLM_new = {
	{
		NTLM_FORMAT_LABEL,
		NTLM_FORMAT_NAME,
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
#if !defined(SIMD_COEF_32) || (defined(SIMD_PARA_MD4) && defined(SSE_OMP))
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAGN },
		ntlm_tests
	}, {
		init,
		done,
		fmt_default_reset,
		ntlm_prepare,
		ntlm_valid,
		ntlm_split,
		get_binary,
		ntlm_get_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			NULL,
			NULL,
			NULL
		},
		salt_hash,
		NULL,
		set_salt,
		set_key_ansi,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			NULL,
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
#endif /* HAVE_LIBCRYPTO */
