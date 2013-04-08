/*
 * NETNTLM_fmt.c -- NTLM Challenge/Response
 *
 * Written by JoMo-Kun <jmk at foofus.net> in 2007
 * and placed in the public domain.
 *
 * Modified for performance, support for SSE2, ESS, OMP and UTF-8, by magnum
 * 2010-2011 and 2013.
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

#include <string.h>
#include <openssl/des.h>

#include "arch.h"
#ifdef MD4_SSE_PARA
#define NBKEYS			(MMX_COEF * MD4_SSE_PARA)
#elif MMX_COEF
#define NBKEYS			MMX_COEF
#else
#ifdef _OPENMP
#define OMP_SCALE		4
#include <omp.h>
#endif
#endif
#include "sse-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "md4.h"
#include "md5.h"
#include "unicode.h"

#ifndef uchar
#define uchar unsigned char
#endif
#define MIN(a, b)		(((a) > (b)) ? (b) : (a))

#define FORMAT_LABEL		"netntlm"
#define FORMAT_NAME		"NTLMv1 C/R MD4 DES (ESS MD5)"
#define ALGORITHM_NAME		MD4_ALGORITHM_NAME
#define BENCHMARK_COMMENT	""
#define BENCHMARK_LENGTH	-1000
#define FULL_BINARY_SIZE	(2 + 8 * 3)
#define BINARY_SIZE		(2 + 8)
#define BINARY_ALIGN            2
#define SALT_SIZE		8
#define SALT_ALIGN              1
#define CIPHERTEXT_LENGTH	48
#define TOTAL_LENGTH		(10 + 2 * 2 * SALT_SIZE + CIPHERTEXT_LENGTH)

#ifdef MMX_COEF
#define PLAINTEXT_LENGTH	27
#ifdef MD4_SSE_PARA
//#define SSE_OMP
#if defined (_OPENMP) && defined(SSE_OMP)
#define BLOCK_LOOPS		(2048 / NBKEYS)
#else
#define BLOCK_LOOPS		(1024 / NBKEYS)
#endif
#else
#define BLOCK_LOOPS		1 /* Only 1 is supported for MMX/SSE asm. */
#endif
#define MIN_KEYS_PER_CRYPT	(NBKEYS * BLOCK_LOOPS)
#define MAX_KEYS_PER_CRYPT	(NBKEYS * BLOCK_LOOPS)
#define GETPOS(i, index)	( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*16*MMX_COEF*4 )
#define GETOUTPOS(i, index)	( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*4*MMX_COEF*4 )
#else
#define PLAINTEXT_LENGTH	64
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	2048
#endif

static struct fmt_tests tests[] = {
	{"$NETNTLM$1122334455667788$BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB", "g3rg3g3rg3g3rg3"},
#ifndef MMX_COEF /* exceeds max length for SSE */
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

#ifdef MMX_COEF
static unsigned char *saved_key;
#ifndef MD4_SSE_PARA
static unsigned int total_len;
#endif
#else
static UTF16 (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_key_length);
#endif

typedef unsigned short HOT_TYPE;
static HOT_TYPE (*crypt_key);
static unsigned char *nthash;
static ARCH_WORD_32 *bitmap;
static int cmps_per_crypt, use_bitmap;
static int valid_i, valid_j;

static uchar *challenge;
static int keys_prepared;

static void set_key_utf8(char *_key, int index);
static void set_key_CP(char *_key, int index);

static void init(struct fmt_main *self)
{
#if defined (_OPENMP) && !defined(MMX_COEF)
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif

	if (options.utf8) {
		self->methods.set_key = set_key_utf8;
		self->params.plaintext_length = MIN(125, 3 * PLAINTEXT_LENGTH);
	} else {
		if (!options.ascii && !options.iso8859_1)
			self->methods.set_key = set_key_CP;
	}
#if MMX_COEF
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * 64 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	nthash = mem_calloc_tiny(sizeof(*nthash) * 16 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	nthash = mem_calloc_tiny(sizeof(*nthash) * 16 * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
#endif
	crypt_key = mem_calloc_tiny(sizeof(HOT_TYPE) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	bitmap = mem_calloc_tiny(0x10000 / 8, MEM_ALIGN_SIMD);
	use_bitmap = 0; /* we did not use bitmap yet */
	cmps_per_crypt = 2; /* try bitmap */
}

static void *get_salt(char *ciphertext);
static inline void setup_des_key(uchar key_56[], DES_key_schedule *ks);

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	if (strncmp(ciphertext, "$NETNTLM$", 9)!=0) return 0;

	if ((strlen(ciphertext) != 74) && (strlen(ciphertext) != 90)) return 0;

	if ((ciphertext[25] != '$') && (ciphertext[41] != '$')) return 0;

	for (pos = &ciphertext[9]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (*pos != '$') return 0;

	for (pos++; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);
	if (!*pos && ((pos - ciphertext - 26 == CIPHERTEXT_LENGTH) ||
	              (pos - ciphertext - 42 == CIPHERTEXT_LENGTH))) {
		uchar key[7] = {0, 0, 0, 0, 0, 0, 0};
		DES_key_schedule ks;
		DES_cblock b3cmp;
		uchar binary[8];
		DES_cblock *challenge = get_salt(ciphertext);
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
		fprintf(stderr, "Rejected NetNTLM hash with invalid 3rd block\n");
#endif
	}
	return 0;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
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

	if (valid(cp,self)) {
		char *cp2 = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cp2;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static char *split(char *ciphertext, int index)
{
	static char out[TOTAL_LENGTH + 1];

	memset(out, 0, TOTAL_LENGTH + 1);
	strncpy(out, ciphertext, TOTAL_LENGTH);
	strlwr(&out[8]); /* Exclude: $NETNTLM$ */

	return out;
}

static inline void setup_des_key(uchar key_56[], DES_key_schedule *ks)
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

static void *get_binary(char *ciphertext)
{
	static uchar *binary;
	static int warned = 0, loaded = 0;
	DES_cblock *challenge = get_salt(ciphertext);
	int i, j;

	if (!binary) binary = mem_alloc_tiny(FULL_BINARY_SIZE, BINARY_ALIGN);

	if (!warned && ++loaded > 100) {
		warned = 1;
		fprintf(stderr, FORMAT_LABEL ": Note: slow loading. For short "
		        "runs, try --format=" FORMAT_LABEL "-naive\ninstead. "
		        "That version loads faster but runs slower.\n");
	}

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

		fprintf(stderr, "Bug: NetNTLM hash with invalid 3rd block, should have been rejected in valid()\n");
		binary[0] = binary[1] = 0x55;
	}

out:
	return binary;
}

static void crypt_all(int count)
{
	if (!keys_prepared) {
		int i = 0;

		if (use_bitmap) {
#if MAX_KEYS_PER_CRYPT >= 200
//#warning Notice: Using memset
			memset(bitmap, 0, 0x10000 / 8);
#else
//#warning Notice: Not using memset
#ifdef MMX_COEF
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

#ifdef MMX_COEF
#if defined(MD4_SSE_PARA)
#if (BLOCK_LOOPS > 1)
#if defined(_OPENMP) && defined(MD4_SSE_PARA) && defined(SSE_OMP)
#pragma omp parallel for
#endif
		for (i = 0; i < BLOCK_LOOPS; i++)
			SSEmd4body(&saved_key[i * NBKEYS * 64], (unsigned int*)&nthash[i * NBKEYS * 16], 1);
#else
		SSEmd4body(saved_key, (unsigned int*)nthash, 1);
#endif
#else
		mdfourmmx(nthash, saved_key, total_len);
#endif
		if (use_bitmap)
		for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++) {
			unsigned int value;

			value = *(ARCH_WORD_32*)&nthash[GETOUTPOS(12, i)] >> 16;
			crypt_key[i] = value;
			bitmap[value >> 5] |= 1U << (value & 0x1f);
		}
		else
		for (i = 0; i < NBKEYS * BLOCK_LOOPS; i++) {
			crypt_key[i] = *(ARCH_WORD_32*)&nthash[GETOUTPOS(12, i)] >> 16;
		}
#else
#if defined(_OPENMP) || (MAX_KEYS_PER_CRYPT > 1)
#ifdef _OPENMP
#pragma omp parallel for
#endif
		for (i = 0; i < count; i++)
#endif
		{
			MD4_CTX ctx;

			MD4_Init( &ctx );
			MD4_Update(&ctx, saved_key[i], saved_key_length[i]);
			MD4_Final((uchar*)&nthash[i * 16], &ctx);

			crypt_key[i] = ((unsigned short*)&nthash[i * 16])[7];
			if (use_bitmap) {
				unsigned int value = crypt_key[i];
				bitmap[value >> 5] |= 1U << (value & 0x1f);
			}
		}
#endif
		keys_prepared = 1;
	}
}

static int cmp_one(void *binary, int index)
{
	if (crypt_key[index] == *(unsigned short*)binary) {
		DES_key_schedule ks;
		DES_cblock computed_binary;
		unsigned int key[2];
#ifdef MMX_COEF
		int i;

		for (i = 0; i < 2; i++)
			key[i] = *(ARCH_WORD_32*)&nthash[GETOUTPOS(4 * i, index)];
#else
		memcpy(key, &nthash[index * 16], 8);
#endif
		setup_des_key((unsigned char*)key, &ks);
		DES_ecb_encrypt((DES_cblock*)challenge, &computed_binary, &ks, DES_ENCRYPT);
		return !memcmp(((char*)binary) + 2, computed_binary, 8);
	}

	return 0;
}

static int cmp_all(void *binary, int count)
{
	unsigned int value = *(unsigned short*)binary;
	int index;

	cmps_per_crypt++;

	if (use_bitmap && !(bitmap[value >> 5] & (1U << (value & 0x1f))))
		goto out;

#ifdef MMX_COEF
	/* Let's give the optimizer a hint! */
	for (index = 0; index < NBKEYS * BLOCK_LOOPS; index += 2) {
#else
	for (index = 0; index < count; index += 2) {
#endif
		unsigned int a = crypt_key[index];
		unsigned int b = crypt_key[index + 1];

#if 0
		if (((a | b) & value) != value)
			continue;
#endif
		if (a == value || b == value)
			goto thorough;
	}

	goto out;

thorough:
#ifdef MMX_COEF
	for (index = 0; index < NBKEYS * BLOCK_LOOPS; index++) {
#else
	for (; index < count; index++) {
#endif
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
	unsigned char key[21];
#ifdef MMX_COEF
	int i;

	for (i = 0; i < 4; i++)
		((ARCH_WORD_32*)key)[i] = *(ARCH_WORD_32*)&nthash[GETOUTPOS(4 * i, index)];
#else
	memcpy(key, &nthash[index * 16], 16);
#endif
	/* Hash is NULL padded to 21-bytes */
	memset(&key[16], 0, 5);

	/* Split into three 7-byte segments for use as DES keys
	   Use each key to DES encrypt challenge
	   Concatenate output to for 24-byte NTLM response */
	setup_des_key(key, &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)binary, &ks, DES_ENCRYPT);
	setup_des_key(&key[7], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[8], &ks, DES_ENCRYPT);
	setup_des_key(&key[14], &ks);
	DES_ecb_encrypt((DES_cblock*)challenge, (DES_cblock*)&binary[16], &ks, DES_ENCRYPT);

	return !memcmp(binary, ((char*)get_binary(source)) + 2, FULL_BINARY_SIZE - 2);
}

static void *get_salt(char *ciphertext)
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

static void set_salt(void *salt)
{
	challenge = salt;
}

static void clear_keys(void)
{
#if defined(MMX_COEF) && !defined(MD4_SSE_PARA)
	total_len = 0;
#endif
}

// ISO-8859-1 to UCS-2, directly into vector key buffer
static void netntlm_set_key(char *_key, int index)
{
#ifdef MMX_COEF
	const uchar *key = (uchar*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
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
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int*)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
#if ARCH_LITTLE_ENDIAN
	UTF8 *s = (UTF8*)_key;
	UTF16 *d = saved_key[index];
	while (*s)
		*d++ = *s++;
	*d = 0;
	saved_key_length[index] = (int)((char*)d - (char*)saved_key[index]);
#else
	UTF8 *s = (UTF8*)_key;
	UTF8 *d = (UTF8*)saved_key[index];
	while (*s) {
		*d++ = *s++;
		++d;
	}
	*d = 0;
	saved_key_length[index] = (int)((char*)d - (char*)saved_key[index]);
#endif
#endif
	keys_prepared = 0;
}

// Legacy codepage to UCS-2, directly into vector key buffer
static void set_key_CP(char *_key, int index)
{
#ifdef MMX_COEF
	const uchar *key = (uchar*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
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
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80;

key_cleaning_enc:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int*)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
	saved_key_length[index] = enc_to_utf16(saved_key[index],
	                                       PLAINTEXT_LENGTH + 1,
	                                       (uchar*)_key,
	                                       strlen(_key)) << 1;
	if (saved_key_length[index] < 0)
		saved_key_length[index] = strlen16(saved_key[index]);
#endif
	keys_prepared = 0;
}

// UTF-8 to UCS-2, directly into vector key buffer
static void set_key_utf8(char *_key, int index)
{
#ifdef MMX_COEF
	const UTF8 *source = (UTF8*)_key;
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
	UTF32 chl, chh = 0x80;
	unsigned int len = 0;

	while (*source) {
		chl = *source;
		if (chl >= 0xC0) {
			unsigned int extraBytesToRead = opt_trailingBytesUTF8[chl & 0x3f];
			switch (extraBytesToRead) {
			case 2:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					return;
			case 1:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else
					return;
			case 0:
				break;
			default:
				return;
			}
			chl -= offsetsFromUTF8[extraBytesToRead];
		}
		source++;
		len++;
		if (*source && len < PLAINTEXT_LENGTH) {
			chh = *source;
			if (chh >= 0xC0) {
				unsigned int extraBytesToRead =
					opt_trailingBytesUTF8[chh & 0x3f];
				switch (extraBytesToRead) {
				case 2:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						return;
				case 1:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else
						return;
				case 0:
					break;
				default:
					return;
				}
				chh -= offsetsFromUTF8[extraBytesToRead];
			}
			source++;
			len++;
		} else {
			chh = 0x80;
			*keybuf_word = (chh << 16) | chl;
			keybuf_word += MMX_COEF;
			break;
		}
		*keybuf_word = (chh << 16) | chl;
		keybuf_word += MMX_COEF;
	}
	if (chh != 0x80 || len == 0) {
		*keybuf_word = 0x80;
		keybuf_word += MMX_COEF;
	}

	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

#ifdef MD4_SSE_PARA
	((unsigned int*)saved_key)[14*MMX_COEF + (index&3) + (index>>2)*16*MMX_COEF] = len << 4;
#else
	total_len += len << (1 + ( (32/MMX_COEF) * index ) );
#endif
#else
	saved_key_length[index] = utf8_to_utf16(saved_key[index],
	                                        PLAINTEXT_LENGTH + 1,
	                                        (uchar*)_key,
	                                        strlen(_key)) << 1;
	if (saved_key_length[index] < 0)
		saved_key_length[index] = strlen16(saved_key[index]);
#endif
	keys_prepared = 0;
}

// Get the key back from the key buffer, from UCS-2
static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int *keybuf_word = (unsigned int*)&saved_key[GETPOS(0, index)];
	static UTF16 key[PLAINTEXT_LENGTH + 1];
	unsigned int md4_size=0;
	unsigned int i=0;

	for(; md4_size < PLAINTEXT_LENGTH; i += MMX_COEF, md4_size++)
	{
		key[md4_size] = keybuf_word[i];
		key[md4_size+1] = keybuf_word[i] >> 16;
		if (key[md4_size] == 0x80 && key[md4_size+1] == 0) {
			key[md4_size] = 0;
			break;
		}
		++md4_size;
		if (key[md4_size] == 0x80 && ((keybuf_word[i+MMX_COEF]&0xFFFF) == 0 || md4_size == PLAINTEXT_LENGTH)) {
			key[md4_size] = 0;
			break;
		}
	}
	return (char*)utf16_to_enc(key);
#else
	return (char*)utf16_to_enc(saved_key[index]);
#endif
}

static int salt_hash(void *salt) { return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1); }

static int binary_hash_0(void *binary) { return *(HOT_TYPE*)binary & 0xF; }
static int binary_hash_1(void *binary) { return *(HOT_TYPE*)binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(HOT_TYPE*)binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(HOT_TYPE*)binary & 0xFFFF; }

static int get_hash_0(int index) { return crypt_key[index] & 0xF; }
static int get_hash_1(int index) { return crypt_key[index] & 0xFF; }
static int get_hash_2(int index) { return crypt_key[index] & 0xFFF; }
static int get_hash_3(int index) { return crypt_key[index] & 0xFFFF; }

struct fmt_main fmt_NETNTLM_new = {
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
#if !defined(MMX_COEF) || (defined(MD4_SSE_PARA) && defined(SSE_OMP))
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		prepare,
		valid,
		split,
		get_binary,
		get_salt,
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
		set_salt,
		netntlm_set_key,
		get_key,
		clear_keys,
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
