/*
 * MSCHAPv2_fmt.c -- Microsoft PPP CHAP Extensions, Version 2
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2010
 * and placed in the public domain.
 *
 * Modified for performance, OMP and utf-8 support
 * by magnum 2010-2011, no rights reserved
 *
 * Modified for using Bitsliced DES by Deepika Dutta Mishra
 * <dipikadutta at gmail.com> in 2012, no rights reserved.
 *
 * Support for freeradius-wep-patch challenge/response format
 * added by Linus Lüssing in 2012 and is licensed under CC0/PD terms:
 *  To the extent possible under law, Linus Lüssing has waived all copyright
 *  and related or neighboring rights to this work. This work is published from: Germany.
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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_MSCHAPv2_old;
#elif FMT_REGISTERS_H
john_register_one(&fmt_MSCHAPv2_old);
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
#include "memory.h"
#include "sha.h"
#include "unicode.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL         "mschapv2-naive"
#define FORMAT_NAME          "MSCHAPv2 C/R"
#define FORMAT_TAG           "$MSCHAPv2$"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME       "MD4 " DES_BS_ALGORITHM_NAME " naive"
#define BENCHMARK_COMMENT    ""
#define BENCHMARK_LENGTH     7
#define PLAINTEXT_LENGTH     125 /* lmcons.h - PWLEN (256) ? 127 ? */
#define USERNAME_LENGTH      256 /* lmcons.h - UNLEN (256) / LM20_UNLEN (20) */
#define DOMAIN_LENGTH        15  /* lmcons.h - CNLEN / DNLEN */
#define BINARY_SIZE          24
#define BINARY_ALIGN         4
#define CHALLENGE_LENGTH     64
#define SALT_SIZE            8
#define SALT_ALIGN           4
#define CIPHERTEXT_LENGTH    48
#define TOTAL_LENGTH         13 + USERNAME_LENGTH + CHALLENGE_LENGTH + CIPHERTEXT_LENGTH

#define MIN_KEYS_PER_CRYPT      DES_BS_DEPTH
#define MAX_KEYS_PER_CRYPT      DES_BS_DEPTH

static struct fmt_tests tests[] = {
	{"", "Cricket8",       {"testuser1",   "", "",    "d07054459a1fdbc266a006f0220e6fac", "33c8331a9b03b7e003f09dd253d740a2bead544143cc8bde", "3545cb1d89b507a5de104435e81b14a4"} },
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

	/* Single test vector from chapcrack's sample pcap file */
	{"$MSCHAPv2$6D0E1C056CD94D5F$1C93ABCE815400686BAECA315F348469256420598A73AD49$moxie", "bPCFyF2uL1p5Lg5yrKmqmY"},

	{"", "clientPass",     {"User",        "", "",    "5B5D7C7D7B3F2F3E3C2C602132262628", "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF", "21402324255E262A28295F2B3A337C7E"} },
	{"", "OMG!BBQ!11!one", {"domain\\fred", "", "",   "56d64cbe7bad61349a0b752335100eaf", "d7d829d9545cef1d631b4e568ffb7586050fa3a4d02dbc0b", "7f8a466cff2a6bf0c80218bbf56d76bc"} }, /* domain\fred */
	{"", "",               {"lameuser", "", "domain", "d94e7c7972b2376b28c268583e162de7", "eba25a3b04d2c7085d01f842e2befc91745c40db0f792356", "0677ca7318fd7f65ae1b4f58c9f4f400"} }, /* no password */
	{"", "asdblahblahblahblahblahblahblahblah", {"WorkGroup\\bOb", "", "", "b3c42db475b881d3c52ff3923d7b3bf8", "f07c7a4eb391f5debe32d814679a5a69661b86b33227c4f8", "6321f8649b971bd11ce8d5cb22a4a738"} }, /* WorkGroup\bOb */

	{NULL}
};

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int (*saved_len);
static uchar (*saved_key)[21];
static uchar *challenge;
static int keys_prepared;
static void set_salt(void *salt);
static char *long_to_short(char *orig); /* used to cannonicalize the format */

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
	saved_len   = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_len));
	saved_key   = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_key));
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(saved_plain);
}

static int valid_long(char *ciphertext)
{
	char *pos, *pos2;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)!=0) return 0;

	if (strlen(ciphertext) > TOTAL_LENGTH)
		return 0;

	/* Validate Authenticator/Server Challenge Length */
	pos = &ciphertext[FORMAT_TAG_LEN];
	for (pos2 = pos; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
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

	if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 2)) )
		return 0;

	/* Validate Username Length */
	if (strlen(++pos2) > USERNAME_LENGTH)
		return 0;

	return 1;
}

static int valid_short(char *ciphertext)
{
	char *pos, *pos2;

	if (ciphertext == NULL) return 0;
	else if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN)!=0) return 0;

	if (strlen(ciphertext) > TOTAL_LENGTH)
		return 0;

	/* Validate MSCHAPv2 Challenge Length */
	pos = &ciphertext[FORMAT_TAG_LEN];
	for (pos2 = pos; *pos2 != '$'; pos2++)
		if (atoi16[ARCH_INDEX(*pos2)] == 0x7F)
			return 0;

	if ( !(*pos2 && (pos2 - pos == CHALLENGE_LENGTH / 4)) )
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

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	return  valid_short(ciphertext) ||
		valid_long(ciphertext);
}

static char *prepare_long(char *split_fields[10])
{
	char *username, *cp;

	/* DOMAIN\USERNAME -or - USERNAME -- ignore DOMAIN */
	if ((username = strstr(split_fields[0], "\\")) == NULL)
		username = split_fields[0];
	else
		username++;

	cp = mem_alloc(FORMAT_TAG_LEN+strlen(split_fields[3])+1+strlen(split_fields[4])+1+strlen(split_fields[5])+1+strlen(username)+1);
	sprintf(cp, "%s%s$%s$%s$%s", FORMAT_TAG, split_fields[3], split_fields[4], split_fields[5], username);
	if (valid_long(cp)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *prepare_short(char *split_fields[10])
{
	char *cp;

	cp = mem_alloc(FORMAT_TAG_LEN+strlen(split_fields[3])+1+strlen(split_fields[4])+1+1+1);
	sprintf(cp, "%s%s$%s$$", FORMAT_TAG, split_fields[3], split_fields[4]);
	if (valid_short(cp)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	char *ret;

	if (!strncmp(split_fields[1], FORMAT_TAG, FORMAT_TAG_LEN)) {
		// check for a short format that has any extra trash fields, and if so remove them.
		char *cp1, *cp2, *cp3;
		static char *out;
		if (!out)
			out = mem_alloc_tiny(FORMAT_TAG_LEN + CHALLENGE_LENGTH/4 + 1 + CIPHERTEXT_LENGTH + 3, MEM_ALIGN_NONE);
		cp1 = split_fields[1];
		cp1 += FORMAT_TAG_LEN;
		cp2 = strchr(cp1, '$');
		ret = NULL;
		if (cp2 && cp2-cp1 == CHALLENGE_LENGTH/4) {
			++cp2;
			cp3 = strchr(cp2, '$');
			if (cp3 && cp3-cp2 == CIPHERTEXT_LENGTH && (strlen(cp3) > 2 || cp3[1] != '$')) {
				ret = out;
				memcpy(ret, split_fields[1], cp3-split_fields[1] + 1);
				ret[(cp3-split_fields[1])+1] = '$';
				ret[(cp3-split_fields[1])+2] = 0;
				//printf("Here is the cut item: %s\n", ret);
			}
		}
	}
	else if (split_fields[0] && split_fields[3] && split_fields[4] && split_fields[5] &&
	        strlen(split_fields[3]) == CHALLENGE_LENGTH/2 &&
	        strlen(split_fields[4]) == CIPHERTEXT_LENGTH &&
	        strlen(split_fields[5]) == CHALLENGE_LENGTH/2)
		ret = prepare_long(split_fields);
	else if (split_fields[0] && split_fields[3] && split_fields[4] &&
	        strlen(split_fields[3]) == CHALLENGE_LENGTH/4 &&
	        strlen(split_fields[4]) == CIPHERTEXT_LENGTH)
		ret = prepare_short(split_fields);
	else
		ret = NULL;

	if (ret && valid_long(ret))
		ret = long_to_short(ret);
	else if (valid_long(split_fields[1]))
		ret = long_to_short(split_fields[1]);

	return ret ? ret : split_fields[1];
}

static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char *out;
	int i, j = 0;

	if (!out) out = mem_alloc_tiny(TOTAL_LENGTH + 1, MEM_ALIGN_WORD);

	memset(out, 0, TOTAL_LENGTH + 1);
	memcpy(out, ciphertext, strlen(ciphertext));

	/* convert hashes to lower-case - exclude $MSCHAPv2 and USERNAME */
	for (i = FORMAT_TAG_LEN; i < TOTAL_LENGTH + 1 && j < 3; i++) {
		if (out[i] >= 'A' && out[i] <= 'Z')
			out[i] |= 0x20;
		else if (out[i] == '$')
			j++;
	}

	if (valid_long(out))
		return long_to_short(out);

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
					block[(chr/4) + (dst>>5)]|= 1U << (dst & 0x1F);
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

	if (valid_short(ciphertext))
		ciphertext += FORMAT_TAG_LEN + CHALLENGE_LENGTH / 4 + 1; /* Skip - $MSCHAPv2$, MSCHAPv2 Challenge */
	else
		ciphertext += FORMAT_TAG_LEN + CHALLENGE_LENGTH / 2 + 1; /* Skip - $MSCHAPv2$, Authenticator Challenge */

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

/* Calculate the MSCHAPv2 response for the given challenge, using the
   specified authentication identity (username), password and client
   nonce.
*/
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

/* Either the cipherext already contains the MSCHAPv2 Challenge (4 Bytes) or
   we are going to calculate it via:
   sha1(|Peer/Client Challenge (8 Bytes)|Authenticator/Server Challenge (8 Bytes)|Username (<=256)|)

   NOTE, we now ONLY call this function the the short form. The long form gets converted into the short
   form in either prepare or split function.  The short form is cannonical form (Change made July, 2014, JimF)
*/
static void *get_salt(char *ciphertext)
{
	static union {
		unsigned char u8[SALT_SIZE];
		uint32_t u32[SALT_SIZE / 4];
	} binary_salt;
	int i, cnt;
	uchar j;
	char *pos = NULL;
	unsigned char temp[SALT_SIZE];

	pos = ciphertext + FORMAT_TAG_LEN;

	for (i = 0; i < SALT_SIZE; i++)
		binary_salt.u8[i] = (atoi16[ARCH_INDEX(pos[i*2])] << 4) + atoi16[ARCH_INDEX(pos[i*2+1])];

	/* Apply IP to salt */
	memset(temp, 0, SALT_SIZE);
	for (i = 0; i < 64; i++) {
		cnt = DES_IP[i ^ 0x20];
		j = (uchar)((binary_salt.u8[cnt >> 3] >> (7 - (cnt & 7))) & 1);
		temp[i/8] |= j << (7 - (i % 8));
	}

	memcpy(binary_salt.u8, temp, SALT_SIZE);
	return (void*)binary_salt.u32;
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
static char *long_to_short(char *ciphertext) {
	static char Buf[TOTAL_LENGTH+1];	// larger than we need, but not a big deal
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

static void set_salt(void *salt)
{
	challenge = salt;
	DES_bs_generate_plaintext(challenge);
}

static void mschapv2_set_key(char *key, int index)
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

struct fmt_main fmt_MSCHAPv2_old = {
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
		FMT_OMP | FMT_OMP_BAD |
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
		mschapv2_set_key,
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
