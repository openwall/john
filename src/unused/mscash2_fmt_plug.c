/* MSCASH2 patch for John the Ripper written by S3nf in 2010, 2011
 * a slow but working version 1.1 ... 1.3
 *
 * Cracking Domain Cached Credentials for modern Windows operating systems, supporting:
 *     - Windows Vista
 *     - Windows 7
 *     - Windows Server 2008
 *
 * This module is based on:
 *     - the MSCASH patch for john written by Alain Espinosa <alainesp at gmail.com> in 2007
 *     - RFC 1320 - The MD4 Message-Digest Algorithm
 *     - RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *     - RFC 3174 - US Secure Hash Algorithm 1 (SHA1)
 *     - the HMAC-SHA1 implementation of the PolarSSL open source cryptagraphic library (http://polarssl.org/)
 *
 * This software was written by S3nf in 2010, 2011. No copyright is claimed, and the software is hereby placed in
 * the public domain. In case this attempt to disclaim copyright and place the software in the public domain
 * is deemed null and void, then the software is Copyright (c) 2010, 2011 S3nf and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Modified for optional utf-8 support by magnum 2011, same terms as above  (v1.2)
 *
 * JimF (June 2011)  (v1.3)
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *   Fixed bug where this format only worked on user names 8 char or less.
 *   Created hmac_sha1_init() function (speedup from 85.2/s to 91.4/s)
 *   xor into dcc2 out using 32 bit (was 8 bit). (speedup from 91.1/s to 92.2/s)
 *
 * TODO, It appears this format should work for user names up to 22 characters (possibly only 21).  However
 * due to implementation within the salt functions, we are only handling upto 19 char user names.  This can
 * be fixed, by having john store a longer salt (45 bytes, vs 44 bytes), and storing the length as 1 byte past
 * the 44 bytes of salt.  In this manner, we can have user names up to max allowed.
 */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"
#include "options.h"

#define ITERATIONS					10240

// MD4 and SHA1 init values
#define INIT_A						0x67452301
#define INIT_B						0xefcdab89
#define INIT_C						0x98badcfe
#define INIT_D						0x10325476
#define INIT_E						0xC3D2E1F0

#define SQRT_2						0x5a827999
#define SQRT_3						0x6ed9eba1

#define SHA1_DIGEST_LENGTH			20

#if ARCH_LITTLE_ENDIAN
#define BESWAP16(n) n
#else
#define BESWAP16(n) ( (n >> 8) | ((n << 8) & 0xffff) )
#endif

#ifndef GET_WORD_32_BE
#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}


/* Note: some tests will be replaced in init() if running UTF-8 */
static struct fmt_tests tests[] = {
	{"M$test1#607bbe89611e37446e736f7856515bf8", "test1" },
	{"bdb80f2c4656a8b8591bd27d39064a54", "\xfc", {"joe"} },       // German u-umlaut in ISO-8859-1
	{"0839e4a07c00f18a8c65cf5b985b9e73", "\xfc\xfc", {"admin"} }, // Two of the above
	{"c0cbe0313a861062e29f92ede58f9b36", "", {"bin"} },           // nullstring password
	{"87136ae0a18b2dafe4a41d555425b2ed", "w00t", {"nineteen_characters"} }, // max salt length
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },

	{"M$TEST2#c6758e5be7fc943d00b97972a8a97620", "test2" },    // salt is lowercased before hashing
	{"M$test3#360e51304a2d383ea33467ab0b639cc4", "test3" },
	{"M$test4#6f79ee93518306f071c47185998566ae", "test4" },

	{NULL}
};

#define FORMAT_LABEL				"mscash2"
#define FORMAT_NAME					"M$ Cache Hash 2"

#define BENCHMARK_COMMENT			""
#define BENCHMARK_LENGTH			-1

#define PLAINTEXT_LENGTH			27
#define MAX_CIPHERTEXT_LENGTH		(2 + 19*3 + 1 + 32) // x3 because salt may be UTF-8 in input

#define ALGORITHM_NAME				"Generic 1x"

#define BINARY_SIZE					16
#define SALT_SIZE					(11*4)

#ifdef _OPENMP
#define MS_NUM_KEYS				64
#else
#define MS_NUM_KEYS				1
#endif
#define MIN_KEYS_PER_CRYPT			1
#define MAX_KEYS_PER_CRYPT			MS_NUM_KEYS

static unsigned int ms_buffer1x[16 * MS_NUM_KEYS];
static unsigned int output1x[4 * MS_NUM_KEYS];
static ARCH_WORD_32 output1x_dcc2[4 * MS_NUM_KEYS];

static unsigned int crypt[4 * MS_NUM_KEYS];
static unsigned int last[4 * MS_NUM_KEYS];

static unsigned int last_i[MS_NUM_KEYS];

#ifdef _OPENMP
static unsigned char _ipad[64 * MS_NUM_KEYS];
static unsigned char _opad[64 * MS_NUM_KEYS];
#else
static unsigned char ipad[64];
static unsigned char opad[64];
#endif

// pre-utf8 was 32, we need up to 3 x PLAINTEXT_LENGTH in theory
#define SAVED_PLAIN_BUF (3 * PLAINTEXT_LENGTH + 1)
static char saved_plain[SAVED_PLAIN_BUF * MS_NUM_KEYS];

static unsigned int *salt_buffer;
static unsigned int salt_len;
static unsigned int new_key;

#ifdef _OPENMP
#include <omp.h>
#endif

static void set_key_utf8(char *_key, int index);
static void *get_salt_utf8(char *ciphertext);
struct fmt_main fmt_mscash2;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int n = omp_get_max_threads();
	if (n < 1)
		n = 1;
	if (n > MS_NUM_KEYS)
		n = MS_NUM_KEYS;
	fmt_mscash2.params.min_keys_per_crypt =
	fmt_mscash2.params.max_keys_per_crypt = n;
#endif
	memset(ms_buffer1x, 0, 64 * MS_NUM_KEYS);
	memset(last_i, 0, 4 * MS_NUM_KEYS);
	new_key = 1;

	if (options.flags & FLG_UTF8) {
		fmt_mscash2.methods.set_key = set_key_utf8;
		fmt_mscash2.methods.salt = get_salt_utf8;
		// UTF8 may be up to three bytes per character
		fmt_mscash2.params.plaintext_length = SAVED_PLAIN_BUF - 1;
		tests[1].plaintext = "\xc3\xbc";         // German u-umlaut in UTF-8
		tests[2].ciphertext = "M$joe#1e1e20f482ff748038e47d801d0d1bda";
		tests[2].plaintext = "\xe2\x82\xac\xe2\x82\xac"; // 2 x Euro signs
	}
}


static char * ms_split(char *ciphertext, int index)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i = 0;

	for(; ciphertext[i] && i < MAX_CIPHERTEXT_LENGTH; i++)
		out[i] = ciphertext[i];

	out[i] = 0;

	// lowercase salt as well as hash
	strlwr(&out[2]);

	return out;
}


static int valid(char *ciphertext, struct fmt_main *self)
{
	unsigned int i;
	unsigned int l;
	char insalt[3*19+1];
	UTF16 realsalt[20];
	int saltlen;

	if (strncmp(ciphertext, "M$", 2))
		return 0;

	l = strlen(ciphertext);
	if (l <= 32 || l > MAX_CIPHERTEXT_LENGTH)
		return 0;

	l -= 32;
	if(ciphertext[l-1]!='#')
		return 0;

	for (i = l; i < l + 32; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	// This is tricky: Max supported salt length is 19 characters of Unicode
	saltlen = plaintowcs(realsalt, 20, (UTF8*)strnzcpy(insalt, &ciphertext[2], l - 2), l - 3);
	if (saltlen < 0 || saltlen > 19)
		return 0;

	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	if (!strncmp(split_fields[1], "M$", 2))
		return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 4);
	sprintf (cp, "M$%s#%s", split_fields[0], split_fields[1]);
	if (valid(cp, self))
	{
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void set_salt(void *salt) {
	salt_buffer = salt;
#if ARCH_LITTLE_ENDIAN
	salt_len = ((salt_buffer[10]>>4)-8)<<1;
#else
	//for (salt_len = 0; ((unsigned char *)salt)[salt_len] != 0x80 && salt_len < 38; salt_len++);
	salt_len = (((salt_buffer[10]>>4)-8)<<1)-1;  // I don't get this but it works
#endif
}


static void *get_salt(char *_ciphertext)
{
	unsigned char *ciphertext = (unsigned char *)_ciphertext;
	// length = 11 for save memory
	// position 10 = length
	// 0-9 = 1-19 Unicode characters + EOS marker (0x80)
	static unsigned int out[11];
	unsigned int md4_size = 0;

	memset(out, 0, 44);

	ciphertext += 2;

	for (;;md4_size++)
		if (ciphertext[md4_size] != '#' && md4_size < 19)
		{
			md4_size++;

			out[md4_size >> 1] = ciphertext[md4_size - 1] | ((ciphertext[md4_size] != '#') ? (ciphertext[md4_size] << 16) : 0x800000);

			if (ciphertext[md4_size] == '#')
				break;
		}
		else
		{
			out[md4_size >> 1] = 0x80;
			break;
		}

	out[10] = (8 + md4_size) << 4;

	return out;
}


static void * get_salt_utf8(char *_ciphertext)
{
	unsigned char *ciphertext = (unsigned char *)_ciphertext;
	static ARCH_WORD_32 out[11];
	unsigned int md4_size=0;
	UTF16 ciphertext_utf16[21];
	int len;

	memset(out,0,sizeof(out));
	ciphertext+=2;
	len = ((unsigned char*)strchr((char*)ciphertext, '#')) - ciphertext;
	utf8towcs(ciphertext_utf16, 20, ciphertext, len + 1);

	for(;;md4_size++) {
#if !ARCH_LITTLE_ENDIAN
		ciphertext_utf16[md4_size] = BESWAP16(ciphertext_utf16[md4_size]);
		ciphertext_utf16[md4_size+1] = BESWAP16(ciphertext_utf16[md4_size+1]);
#endif
		if(ciphertext_utf16[md4_size]!=(UTF16)'#' && md4_size < 19) {
			md4_size++;
			out[md4_size>>1] = ciphertext_utf16[md4_size-1] |
				((ciphertext_utf16[md4_size]!=(UTF16)'#') ?
				 (ciphertext_utf16[md4_size]<<16) : 0x800000);

			if(ciphertext_utf16[md4_size]==(UTF16)'#')
				break;
		}
		else {
			out[md4_size>>1] = 0x80;
			break;
		}
	}

	out[10] = (8 + md4_size) << 4;

	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned int out[4];
	unsigned int i = 0;
	unsigned int temp;

	for (; ciphertext[0] != '#'; ciphertext++);
	ciphertext++;

	for (; i < 4 ;i++)
	{
		temp  = (atoi16[ARCH_INDEX(ciphertext[i * 8 + 0])]) << 4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 1])]);

		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 2])]) << 12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 3])]) << 8;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 4])]) << 20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 5])]) << 16;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 6])]) << 28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 7])]) << 24;

		out[i] = temp;
	}

	return out;
}


static int binary_hash_0(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0F;
}


static int binary_hash_1(void *binary)
{
	return ((unsigned int*)binary)[3] & 0xFF;
}


static int binary_hash_2(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0FFF;
}


static int binary_hash_3(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0FFFF;
}


static int binary_hash_4(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0FFFFF;
}


static int get_hash_0(int index)
{
	return output1x_dcc2[4 * index + 3] & 0x0F;
}


static int get_hash_1(int index)
{
	return output1x_dcc2[4 * index + 3] & 0xFF;
}


static int get_hash_2(int index)
{
	return output1x_dcc2[4 * index + 3] & 0x0FFF;
}


static int get_hash_3(int index)
{
	return output1x_dcc2[4 * index + 3] & 0x0FFFF;
}


static int get_hash_4(int index)
{
	return output1x_dcc2[4 * index + 3] & 0x0FFFFF;
}


static void nt_hash(int count)
{
	int i;

#if MS_NUM_KEYS > 1 && defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, ms_buffer1x, crypt, last)
#endif
	for(i = 0; i < count; i++)
	{
		unsigned int a;
		unsigned int b;
		unsigned int c;
		unsigned int d;

		// round 1
		a =	0xFFFFFFFF + ms_buffer1x[16 * i + 0]; a = (a << 3 ) | (a >> 29);
		d = INIT_D + (INIT_C ^ (a & 0x77777777)) + ms_buffer1x[16 * i +1]; d = (d << 7 ) | (d >> 25);
		c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B))) + ms_buffer1x[16 * i +2]; c = (c << 11) | (c >> 21);
		b = INIT_B + (a ^ (c & (d ^ a))) + ms_buffer1x[16 * i +3]; b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16 * i + 4]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16 * i + 5]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16 * i + 6]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a))) + ms_buffer1x[16 * i + 7]  ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16 * i + 8]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16 * i + 9]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16 * i + 10] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a))) + ms_buffer1x[16 * i + 11] ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16 * i + 12] ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16 * i + 13] ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16 * i + 14] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))/* + ms_buffer1x[16 * i + 15]*/;b = (b << 19) | (b >> 13);

		// round 2
		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16 * i + 0]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16 * i + 4]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16 * i + 8]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16 * i + 12] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16 * i + 1]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16 * i + 5]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16 * i + 9]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16 * i + 13] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16 * i + 2]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16 * i + 6]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16 * i + 10] + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16 * i + 14] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16 * i + 3]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16 * i + 7]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16 * i + 11] + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))/* + ms_buffer1x[ 16 * i + 15]*/+SQRT_2; b = (b << 13) | (b >> 19);

		// round 3
		a += (b ^ c ^ d) + ms_buffer1x[16 * i + 0]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16 * i + 8]  + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16 * i + 4]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16 * i + 12] + SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + ms_buffer1x[16 * i + 2]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16 * i + 10] + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16 * i + 6]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16 * i + 14] + SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + ms_buffer1x[16 * i + 1]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16 * i + 9]  + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16 * i + 5]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16 * i + 13] + SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + ms_buffer1x[16 * i + 3]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16 * i + 11] + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16 * i + 7]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) /*+ ms_buffer1x[16 * i + 15] */+ SQRT_3; b = (b << 15) | (b >> 17);

		crypt[4 * i + 0] = a + INIT_A;
		crypt[4 * i + 1] = b + INIT_B;
		crypt[4 * i + 2] = c + INIT_C;
		crypt[4 * i + 3] = d + INIT_D;

		// another MD4 crypt for the salt
		// round 1
		a =  0xFFFFFFFF + crypt[ 4 * i + 0]; a = ( a << 3 )| ( a >> 29);
		d = INIT_D + (INIT_C ^ (a & 0x77777777)) + crypt[4 * i + 1]; d =(d << 7 ) | (d >> 25);
		c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B))) + crypt[4 * i + 2]; c = (c << 11) | (c >> 21);
		b = INIT_B + (a ^ (c & (d ^ a))) + crypt[4 * i + 3]; b = (b << 19) |(b >> 13);

		last[4 * i + 0] = a;
		last[4 * i + 1] = b;
		last[4 * i + 2] = c;
		last[4 * i + 3] = d;
	}
}


/*
 * hmac_sha1
 * based on RFC 2104, RFC 3174 and the HMAC-SHA1 implementation of the PolarSSL
 * open source cryptographic library (http://www.polarssl.org)
 */

/* Creating an hmac_sha1_init function, and ONLY calling it one time, sped up the
 * runtime on my machine from 85.2/s to 91.4/s  JimF  (June 21, 2011) */
static void hmac_sha1_init(const unsigned char *key, unsigned int keylen, unsigned idx)
{
	unsigned int i;

#ifdef _OPENMP
	unsigned char *ipad, *opad;
	ipad = &_ipad[64*idx];
	opad = &_opad[64*idx];
#endif
	memset(ipad, 0x36, 64);
	memset(opad, 0x5C, 64);
	for(i = 0; i < keylen; i++)
	{
		ipad[i] = ipad[i] ^ key[i];
		opad[i] = opad[i] ^ key[i];
	}
}

static void hmac_sha1(const unsigned char *input, unsigned int inputlen, unsigned char *output, unsigned idx) {

	unsigned int temp, W[16];
	unsigned int A, B, C, D, E, state[5];
	unsigned char buf[64];

#ifdef _OPENMP
	unsigned char *ipad, *opad;

	ipad = &_ipad[64*idx];
	opad = &_opad[64*idx];
#endif

	memset(buf, 0, 64);

	// step 1: append zeros to the end of K to create a B Byte string
	memcpy(buf, input, inputlen);
	buf[inputlen] = 0x80;

#if ARCH_LITTLE_ENDIAN || !ARCH_ALLOWS_UNALIGNED
	PUT_WORD_32_BE((64 + inputlen) << 3, buf, 60);
#else
	((unsigned int *)buf)[15] = (64 + inputlen) << 3;
#endif

	// step 2: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with ipad
	// step 5: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with opad

	// step 3: append the stream of data 'text' to the B byte sting resulting from step 2
	// first part of stream (64 bytes) is ipad, second part of stream (64 bytes) is buf

	// step 4: apply H to the stream (ipad & buf) generated in step 3
#if ARCH_LITTLE_ENDIAN
	GET_WORD_32_BE(W[ 0], ipad,  0);
	GET_WORD_32_BE(W[ 1], ipad,  4);
	GET_WORD_32_BE(W[ 2], ipad,  8);
	GET_WORD_32_BE(W[ 3], ipad, 12);
	GET_WORD_32_BE(W[ 4], ipad, 16);
	GET_WORD_32_BE(W[ 5], ipad, 20);
	GET_WORD_32_BE(W[ 6], ipad, 24);
	GET_WORD_32_BE(W[ 7], ipad, 28);
	GET_WORD_32_BE(W[ 8], ipad, 32);
	GET_WORD_32_BE(W[ 9], ipad, 36);
	GET_WORD_32_BE(W[10], ipad, 40);
	GET_WORD_32_BE(W[11], ipad, 44);
	GET_WORD_32_BE(W[12], ipad, 48);
	GET_WORD_32_BE(W[13], ipad, 52);
	GET_WORD_32_BE(W[14], ipad, 56);
	GET_WORD_32_BE(W[15], ipad, 60);
#else
	memcpy(W, ipad, 64);
#endif

	A = INIT_A;
	B = INIT_B;
	C = INIT_C;
	D = INIT_D;
	E = INIT_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W[0] );
	P(E, A, B, C, D, W[1] );
	P(D, E, A, B, C, W[2] );
	P(C, D, E, A, B, W[3] );
	P(B, C, D, E, A, W[4] );
	P(A, B, C, D, E, W[5] );
	P(E, A, B, C, D, W[6] );
	P(D, E, A, B, C, W[7] );
	P(C, D, E, A, B, W[8] );
	P(B, C, D, E, A, W[9] );
	P(A, B, C, D, E, W[10]);
	P(E, A, B, C, D, W[11]);
	P(D, E, A, B, C, W[12]);
	P(C, D, E, A, B, W[13]);
	P(B, C, D, E, A, W[14]);
	P(A, B, C, D, E, W[15]);
	P(E, A, B, C, D, R(16));
	P(D, E, A, B, C, R(17));
	P(C, D, E, A, B, R(18));
	P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R(20));
	P(E, A, B, C, D, R(21));
	P(D, E, A, B, C, R(22));
	P(C, D, E, A, B, R(23));
	P(B, C, D, E, A, R(24));
	P(A, B, C, D, E, R(25));
	P(E, A, B, C, D, R(26));
	P(D, E, A, B, C, R(27));
	P(C, D, E, A, B, R(28));
	P(B, C, D, E, A, R(29));
	P(A, B, C, D, E, R(30));
	P(E, A, B, C, D, R(31));
	P(D, E, A, B, C, R(32));
	P(C, D, E, A, B, R(33));
	P(B, C, D, E, A, R(34));
	P(A, B, C, D, E, R(35));
	P(E, A, B, C, D, R(36));
	P(D, E, A, B, C, R(37));
	P(C, D, E, A, B, R(38));
	P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R(40));
	P(E, A, B, C, D, R(41));
	P(D, E, A, B, C, R(42));
	P(C, D, E, A, B, R(43));
	P(B, C, D, E, A, R(44));
	P(A, B, C, D, E, R(45));
	P(E, A, B, C, D, R(46));
	P(D, E, A, B, C, R(47));
	P(C, D, E, A, B, R(48));
	P(B, C, D, E, A, R(49));
	P(A, B, C, D, E, R(50));
	P(E, A, B, C, D, R(51));
	P(D, E, A, B, C, R(52));
	P(C, D, E, A, B, R(53));
	P(B, C, D, E, A, R(54));
	P(A, B, C, D, E, R(55));
	P(E, A, B, C, D, R(56));
	P(D, E, A, B, C, R(57));
	P(C, D, E, A, B, R(58));
	P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, R(60));
	P(E, A, B, C, D, R(61));
	P(D, E, A, B, C, R(62));
	P(C, D, E, A, B, R(63));
	P(B, C, D, E, A, R(64));
	P(A, B, C, D, E, R(65));
	P(E, A, B, C, D, R(66));
	P(D, E, A, B, C, R(67));
	P(C, D, E, A, B, R(68));
	P(B, C, D, E, A, R(69));
	P(A, B, C, D, E, R(70));
	P(E, A, B, C, D, R(71));
	P(D, E, A, B, C, R(72));
	P(C, D, E, A, B, R(73));
	P(B, C, D, E, A, R(74));
	P(A, B, C, D, E, R(75));
	P(E, A, B, C, D, R(76));
	P(D, E, A, B, C, R(77));
	P(C, D, E, A, B, R(78));
	P(B, C, D, E, A, R(79));

#undef K
#undef F

	A += INIT_A;
	B += INIT_B;
	C += INIT_C;
	D += INIT_D;
	E += INIT_E;

	state[0] = A;
	state[1] = B;
	state[2] = C;
	state[3] = D;
	state[4] = E;

	// process buf (2nd part of stream)
#if ARCH_LITTLE_ENDIAN
	GET_WORD_32_BE(W[ 0], buf,  0);
	GET_WORD_32_BE(W[ 1], buf,  4);
	GET_WORD_32_BE(W[ 2], buf,  8);
	GET_WORD_32_BE(W[ 3], buf, 12);
	GET_WORD_32_BE(W[ 4], buf, 16);
	GET_WORD_32_BE(W[ 5], buf, 20);
	GET_WORD_32_BE(W[ 6], buf, 24);
	GET_WORD_32_BE(W[ 7], buf, 28);
	GET_WORD_32_BE(W[ 8], buf, 32);
	GET_WORD_32_BE(W[ 9], buf, 36);
	GET_WORD_32_BE(W[10], buf, 40);
	GET_WORD_32_BE(W[11], buf, 44);
	GET_WORD_32_BE(W[12], buf, 48);
	GET_WORD_32_BE(W[13], buf, 52);
	GET_WORD_32_BE(W[14], buf, 56);
	GET_WORD_32_BE(W[15], buf, 60);
#else
	memcpy(W, buf, 64);
#endif

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W[0] );
	P(E, A, B, C, D, W[1] );
	P(D, E, A, B, C, W[2] );
	P(C, D, E, A, B, W[3] );
	P(B, C, D, E, A, W[4] );
	P(A, B, C, D, E, W[5] );
	P(E, A, B, C, D, W[6] );
	P(D, E, A, B, C, W[7] );
	P(C, D, E, A, B, W[8] );
	P(B, C, D, E, A, W[9] );
	P(A, B, C, D, E, W[10]);
	P(E, A, B, C, D, W[11]);
	P(D, E, A, B, C, W[12]);
	P(C, D, E, A, B, W[13]);
	P(B, C, D, E, A, W[14]);
	P(A, B, C, D, E, W[15]);
	P(E, A, B, C, D, R(16));
	P(D, E, A, B, C, R(17));
	P(C, D, E, A, B, R(18));
	P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R(20));
	P(E, A, B, C, D, R(21));
	P(D, E, A, B, C, R(22));
	P(C, D, E, A, B, R(23));
	P(B, C, D, E, A, R(24));
	P(A, B, C, D, E, R(25));
	P(E, A, B, C, D, R(26));
	P(D, E, A, B, C, R(27));
	P(C, D, E, A, B, R(28));
	P(B, C, D, E, A, R(29));
	P(A, B, C, D, E, R(30));
	P(E, A, B, C, D, R(31));
	P(D, E, A, B, C, R(32));
	P(C, D, E, A, B, R(33));
	P(B, C, D, E, A, R(34));
	P(A, B, C, D, E, R(35));
	P(E, A, B, C, D, R(36));
	P(D, E, A, B, C, R(37));
	P(C, D, E, A, B, R(38));
	P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R(40));
	P(E, A, B, C, D, R(41));
	P(D, E, A, B, C, R(42));
	P(C, D, E, A, B, R(43));
	P(B, C, D, E, A, R(44));
	P(A, B, C, D, E, R(45));
	P(E, A, B, C, D, R(46));
	P(D, E, A, B, C, R(47));
	P(C, D, E, A, B, R(48));
	P(B, C, D, E, A, R(49));
	P(A, B, C, D, E, R(50));
	P(E, A, B, C, D, R(51));
	P(D, E, A, B, C, R(52));
	P(C, D, E, A, B, R(53));
	P(B, C, D, E, A, R(54));
	P(A, B, C, D, E, R(55));
	P(E, A, B, C, D, R(56));
	P(D, E, A, B, C, R(57));
	P(C, D, E, A, B, R(58));
	P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, R(60));
	P(E, A, B, C, D, R(61));
	P(D, E, A, B, C, R(62));
	P(C, D, E, A, B, R(63));
	P(B, C, D, E, A, R(64));
	P(A, B, C, D, E, R(65));
	P(E, A, B, C, D, R(66));
	P(D, E, A, B, C, R(67));
	P(C, D, E, A, B, R(68));
	P(B, C, D, E, A, R(69));
	P(A, B, C, D, E, R(70));
	P(E, A, B, C, D, R(71));
	P(D, E, A, B, C, R(72));
	P(C, D, E, A, B, R(73));
	P(B, C, D, E, A, R(74));
	P(A, B, C, D, E, R(75));
	P(E, A, B, C, D, R(76));
	P(D, E, A, B, C, R(77));
	P(C, D, E, A, B, R(78));
	P(B, C, D, E, A, R(79));

#undef K
#undef F

	A += state[0];
	B += state[1];
	C += state[2];
	D += state[3];
	E += state[4];

	if (inputlen > 20)
		memset(&buf[21], 0, inputlen-20);  // will nuke extra input, and the original 0x20

#if ARCH_LITTLE_ENDIAN || !ARCH_ALLOWS_UNALIGNED
	PUT_WORD_32_BE(A, buf,  0);
	PUT_WORD_32_BE(B, buf,  4);
	PUT_WORD_32_BE(C, buf,  8);
	PUT_WORD_32_BE(D, buf, 12);
	PUT_WORD_32_BE(E, buf, 16);

	buf[20] = 0x80;
	PUT_WORD_32_BE(0x2A0, buf, 60);
#else
	((unsigned int *)buf)[0] = A;
	((unsigned int *)buf)[1] = B;
	((unsigned int *)buf)[2] = C;
	((unsigned int *)buf)[3] = D;
	((unsigned int *)buf)[4] = E;

	buf[20] = 0x80;
	((unsigned int *)buf)[15] = 0x2A0;
#endif

	// step 6: append the stream of data 'text' to the B byte sting resulting from step 2
	// first part of stream (64 bytes) is opad, second part of stream (64 bytes) is the H result from step 4

	// step 7: apply H to the stream (opad & buf) generated in step 6 and output the result
#if ARCH_LITTLE_ENDIAN
	GET_WORD_32_BE(W[ 0], opad,  0);
	GET_WORD_32_BE(W[ 1], opad,  4);
	GET_WORD_32_BE(W[ 2], opad,  8);
	GET_WORD_32_BE(W[ 3], opad, 12);
	GET_WORD_32_BE(W[ 4], opad, 16);
	GET_WORD_32_BE(W[ 5], opad, 20);
	GET_WORD_32_BE(W[ 6], opad, 24);
	GET_WORD_32_BE(W[ 7], opad, 28);
	GET_WORD_32_BE(W[ 8], opad, 32);
	GET_WORD_32_BE(W[ 9], opad, 36);
	GET_WORD_32_BE(W[10], opad, 40);
	GET_WORD_32_BE(W[11], opad, 44);
	GET_WORD_32_BE(W[12], opad, 48);
	GET_WORD_32_BE(W[13], opad, 52);
	GET_WORD_32_BE(W[14], opad, 56);
	GET_WORD_32_BE(W[15], opad, 60);
#else
	memcpy(W, opad, 64);
#endif

	A = INIT_A;
	B = INIT_B;
	C = INIT_C;
	D = INIT_D;
	E = INIT_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W[0] );
	P(E, A, B, C, D, W[1] );
	P(D, E, A, B, C, W[2] );
	P(C, D, E, A, B, W[3] );
	P(B, C, D, E, A, W[4] );
	P(A, B, C, D, E, W[5] );
	P(E, A, B, C, D, W[6] );
	P(D, E, A, B, C, W[7] );
	P(C, D, E, A, B, W[8] );
	P(B, C, D, E, A, W[9] );
	P(A, B, C, D, E, W[10]);
	P(E, A, B, C, D, W[11]);
	P(D, E, A, B, C, W[12]);
	P(C, D, E, A, B, W[13]);
	P(B, C, D, E, A, W[14]);
	P(A, B, C, D, E, W[15]);
	P(E, A, B, C, D, R(16));
	P(D, E, A, B, C, R(17));
	P(C, D, E, A, B, R(18));
	P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R(20));
	P(E, A, B, C, D, R(21));
	P(D, E, A, B, C, R(22));
	P(C, D, E, A, B, R(23));
	P(B, C, D, E, A, R(24));
	P(A, B, C, D, E, R(25));
	P(E, A, B, C, D, R(26));
	P(D, E, A, B, C, R(27));
	P(C, D, E, A, B, R(28));
	P(B, C, D, E, A, R(29));
	P(A, B, C, D, E, R(30));
	P(E, A, B, C, D, R(31));
	P(D, E, A, B, C, R(32));
	P(C, D, E, A, B, R(33));
	P(B, C, D, E, A, R(34));
	P(A, B, C, D, E, R(35));
	P(E, A, B, C, D, R(36));
	P(D, E, A, B, C, R(37));
	P(C, D, E, A, B, R(38));
	P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R(40));
	P(E, A, B, C, D, R(41));
	P(D, E, A, B, C, R(42));
	P(C, D, E, A, B, R(43));
	P(B, C, D, E, A, R(44));
	P(A, B, C, D, E, R(45));
	P(E, A, B, C, D, R(46));
	P(D, E, A, B, C, R(47));
	P(C, D, E, A, B, R(48));
	P(B, C, D, E, A, R(49));
	P(A, B, C, D, E, R(50));
	P(E, A, B, C, D, R(51));
	P(D, E, A, B, C, R(52));
	P(C, D, E, A, B, R(53));
	P(B, C, D, E, A, R(54));
	P(A, B, C, D, E, R(55));
	P(E, A, B, C, D, R(56));
	P(D, E, A, B, C, R(57));
	P(C, D, E, A, B, R(58));
	P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, R(60));
	P(E, A, B, C, D, R(61));
	P(D, E, A, B, C, R(62));
	P(C, D, E, A, B, R(63));
	P(B, C, D, E, A, R(64));
	P(A, B, C, D, E, R(65));
	P(E, A, B, C, D, R(66));
	P(D, E, A, B, C, R(67));
	P(C, D, E, A, B, R(68));
	P(B, C, D, E, A, R(69));
	P(A, B, C, D, E, R(70));
	P(E, A, B, C, D, R(71));
	P(D, E, A, B, C, R(72));
	P(C, D, E, A, B, R(73));
	P(B, C, D, E, A, R(74));
	P(A, B, C, D, E, R(75));
	P(E, A, B, C, D, R(76));
	P(D, E, A, B, C, R(77));
	P(C, D, E, A, B, R(78));
	P(B, C, D, E, A, R(79));

#undef K
#undef F

	A += INIT_A;
	B += INIT_B;
	C += INIT_C;
	D += INIT_D;
	E += INIT_E;

	// store state for 2nd part
	state[0] = A;
	state[1] = B;
	state[2] = C;
	state[3] = D;
	state[4] = E;

#if ARCH_LITTLE_ENDIAN
	GET_WORD_32_BE(W[ 0], buf,  0);
	GET_WORD_32_BE(W[ 1], buf,  4);
	GET_WORD_32_BE(W[ 2], buf,  8);
	GET_WORD_32_BE(W[ 3], buf, 12);
	GET_WORD_32_BE(W[ 4], buf, 16);
	GET_WORD_32_BE(W[ 5], buf, 20);
	GET_WORD_32_BE(W[ 6], buf, 24);
	GET_WORD_32_BE(W[ 7], buf, 28);
	GET_WORD_32_BE(W[ 8], buf, 32);
	GET_WORD_32_BE(W[ 9], buf, 36);
	GET_WORD_32_BE(W[10], buf, 40);
	GET_WORD_32_BE(W[11], buf, 44);
	GET_WORD_32_BE(W[12], buf, 48);
	GET_WORD_32_BE(W[13], buf, 52);
	GET_WORD_32_BE(W[14], buf, 56);
	GET_WORD_32_BE(W[15], buf, 60);
#else
	memcpy(W, buf, 64);
#endif

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

	P(A, B, C, D, E, W[0] );
	P(E, A, B, C, D, W[1] );
	P(D, E, A, B, C, W[2] );
	P(C, D, E, A, B, W[3] );
	P(B, C, D, E, A, W[4] );
	P(A, B, C, D, E, W[5] );
	P(E, A, B, C, D, W[6] );
	P(D, E, A, B, C, W[7] );
	P(C, D, E, A, B, W[8] );
	P(B, C, D, E, A, W[9] );
	P(A, B, C, D, E, W[10]);
	P(E, A, B, C, D, W[11]);
	P(D, E, A, B, C, W[12]);
	P(C, D, E, A, B, W[13]);
	P(B, C, D, E, A, W[14]);
	P(A, B, C, D, E, W[15]);
	P(E, A, B, C, D, R(16));
	P(D, E, A, B, C, R(17));
	P(C, D, E, A, B, R(18));
	P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

	P(A, B, C, D, E, R(20));
	P(E, A, B, C, D, R(21));
	P(D, E, A, B, C, R(22));
	P(C, D, E, A, B, R(23));
	P(B, C, D, E, A, R(24));
	P(A, B, C, D, E, R(25));
	P(E, A, B, C, D, R(26));
	P(D, E, A, B, C, R(27));
	P(C, D, E, A, B, R(28));
	P(B, C, D, E, A, R(29));
	P(A, B, C, D, E, R(30));
	P(E, A, B, C, D, R(31));
	P(D, E, A, B, C, R(32));
	P(C, D, E, A, B, R(33));
	P(B, C, D, E, A, R(34));
	P(A, B, C, D, E, R(35));
	P(E, A, B, C, D, R(36));
	P(D, E, A, B, C, R(37));
	P(C, D, E, A, B, R(38));
	P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

	P(A, B, C, D, E, R(40));
	P(E, A, B, C, D, R(41));
	P(D, E, A, B, C, R(42));
	P(C, D, E, A, B, R(43));
	P(B, C, D, E, A, R(44));
	P(A, B, C, D, E, R(45));
	P(E, A, B, C, D, R(46));
	P(D, E, A, B, C, R(47));
	P(C, D, E, A, B, R(48));
	P(B, C, D, E, A, R(49));
	P(A, B, C, D, E, R(50));
	P(E, A, B, C, D, R(51));
	P(D, E, A, B, C, R(52));
	P(C, D, E, A, B, R(53));
	P(B, C, D, E, A, R(54));
	P(A, B, C, D, E, R(55));
	P(E, A, B, C, D, R(56));
	P(D, E, A, B, C, R(57));
	P(C, D, E, A, B, R(58));
	P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

	P(A, B, C, D, E, R(60));
	P(E, A, B, C, D, R(61));
	P(D, E, A, B, C, R(62));
	P(C, D, E, A, B, R(63));
	P(B, C, D, E, A, R(64));
	P(A, B, C, D, E, R(65));
	P(E, A, B, C, D, R(66));
	P(D, E, A, B, C, R(67));
	P(C, D, E, A, B, R(68));
	P(B, C, D, E, A, R(69));
	P(A, B, C, D, E, R(70));
	P(E, A, B, C, D, R(71));
	P(D, E, A, B, C, R(72));
	P(C, D, E, A, B, R(73));
	P(B, C, D, E, A, R(74));
	P(A, B, C, D, E, R(75));
	P(E, A, B, C, D, R(76));
	P(D, E, A, B, C, R(77));
	P(C, D, E, A, B, R(78));
	P(B, C, D, E, A, R(79));

#undef K
#undef F

	A += state[0];
	B += state[1];
	C += state[2];
	D += state[3];
	E += state[4];

#if ARCH_LITTLE_ENDIAN || !ARCH_ALLOWS_UNALIGNED
	PUT_WORD_32_BE(A, output,  0);
	PUT_WORD_32_BE(B, output,  4);
	PUT_WORD_32_BE(C, output,  8);
	PUT_WORD_32_BE(D, output, 12);
	PUT_WORD_32_BE(E, output, 16);
#else
	((unsigned int *)output)[0] = A;
	((unsigned int *)output)[1] = B;
	((unsigned int *)output)[2] = C;
	((unsigned int *)output)[3] = D;
	((unsigned int *)output)[4] = E;
#endif
}


/* PBKDF2
 * stripped-down implementation
 * based on the source code written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL Project 1999
 */
static void PBKDF2_DCC2(const unsigned char *pass, const unsigned char *salt, int saltlen, ARCH_WORD_32 *out, int idx)
{
	ARCH_WORD_32 temp[SHA1_DIGEST_LENGTH/4];
	unsigned char buf[48];
	unsigned int i;

	memset(buf, 0, 48);
#if ARCH_LITTLE_ENDIAN
	memcpy(buf, salt, saltlen);
#else
	// do some big endian byte shifting with the salt
	unsigned int v;

	saltlen++;

	for (i = 0; i < saltlen / 4; i++)
	{
		v = ((unsigned int *)salt)[i];
		((unsigned int *)buf)[i] = (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00) | (v << 24);
	}

	if (saltlen % 4 != 0)
	{
		v = ((unsigned int *)salt)[i] & 0x000000FF;
		((unsigned int *)buf)[i] = (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00) | (v << 24);

	}
#endif
	buf[saltlen + 3] = 0x01;

	hmac_sha1_init(pass, 16, idx);
	hmac_sha1(buf, saltlen + 4, (unsigned char*)temp, idx);

	memcpy(out, temp, 16);

	for (i = 1; i < ITERATIONS; i++)
	{
		hmac_sha1((unsigned char*)temp, SHA1_DIGEST_LENGTH, (unsigned char*)temp, idx);
		out[0] ^= temp[0];
		out[1] ^= temp[1];
		out[2] ^= temp[2];
		out[3] ^= temp[3];
	}

#if !ARCH_LITTLE_ENDIAN
	v = ((unsigned int *)out)[0];
	((unsigned int *)out)[0] = (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00) | (v << 24);
	v = ((unsigned int *)out)[1];
	((unsigned int *)out)[1] = (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00) | (v << 24);
	v = ((unsigned int *)out)[2];
	((unsigned int *)out)[2] = (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00) | (v << 24);
	v = ((unsigned int *)out)[3];
	((unsigned int *)out)[3] = (v >> 24) | ((v << 8) & 0x00FF0000) | ((v >> 8) & 0x0000FF00) | (v << 24);
#endif
}


static void crypt_all(int count)
{
	int i;

	if (new_key)
	{
		new_key = 0;
		nt_hash(count);
	}

#if MS_NUM_KEYS > 1 && defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, last, salt_buffer, salt_len, crypt, output1x, output1x_dcc2)
#endif
	for (i = 0; i < count; i++)
	{
		unsigned int a;
		unsigned int b;
		unsigned int c;
		unsigned int d;

		a = last[4 * i + 0];
		b = last[4 * i + 1];
		c = last[4 * i + 2];
		d = last[4 * i + 3];

		a += (d ^ (b & (c ^ d)))  + salt_buffer[0]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[1]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[2]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))  + salt_buffer[3]  ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d)))  + salt_buffer[4]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[5]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[6]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))  + salt_buffer[7]  ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d)))  + salt_buffer[8]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c)))  + salt_buffer[9]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b)))  + salt_buffer[10] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))/*+salt_buffer[11]*/;b = (b << 19) | (b >> 13);

		// round 2
		a += ((b & (c | d)) | (c & d))  +  crypt[4 * i + 0] + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[0]   + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[4]   + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[8]   + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt[4 * i + 1] + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[1]   + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[5]   + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[9]   + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt[4 * i + 2] + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[2]   + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[6]   + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[10]  + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt[4 * i + 3] + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[3]   + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[7]   + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))/*+ salt_buffer[11]*/ + SQRT_2; b = (b << 13) | (b >> 19);

		// round 3
		a += (b ^ c ^ d) + crypt[4 * i + 0] +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[4]   +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[0]   +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[8]   +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + crypt[4 * i + 2] +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[6]   +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[2]   +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[10]  +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + crypt[4 * i + 1] + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[5]   + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[1]   + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[9]   + SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + crypt[4 * i + 3] + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[7]   + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[3]   + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) /*+ salt_buffer[11] */ + SQRT_3; b = (b << 15) | (b >> 17);

#if ARCH_LITTLE_ENDIAN
		output1x[4 * i + 0] = a + INIT_A;
		output1x[4 * i + 1] = b + INIT_B;
		output1x[4 * i + 2] = c + INIT_C;
		output1x[4 * i + 3] = d + INIT_D;
#else
		a = a + INIT_A;
		b = b + INIT_B;
		c = c + INIT_C;
		d = d + INIT_D;

		output1x[4 * i + 0] = (a >> 24) | ((a << 8) & 0x00FF0000) | ((a >> 8) & 0x0000FF00) | (a << 24);
		output1x[4 * i + 1] = (b >> 24) | ((b << 8) & 0x00FF0000) | ((b >> 8) & 0x0000FF00) | (b << 24);
		output1x[4 * i + 2] = (c >> 24) | ((c << 8) & 0x00FF0000) | ((c >> 8) & 0x0000FF00) | (c << 24);
		output1x[4 * i + 3] = (d >> 24) | ((d << 8) & 0x00FF0000) | ((d >> 8) & 0x0000FF00) | (d << 24);
#endif
		// PBKDF2 for new Domain Cached Credentials (MS Cash 2)
		PBKDF2_DCC2((unsigned char *)&output1x[4 * i], (unsigned char *)salt_buffer, salt_len, &output1x_dcc2[4 * i], i);
	}
}


static int cmp_all(void *binary, int count)
{
	unsigned int i = 0;
	unsigned int d = ((unsigned int *)binary)[3];

	for (; i < count; i++)
		if (d == output1x_dcc2[i * 4 + 3])
			return 1;

	return 0;
}


static int cmp_one(void * binary, int index)
{
	unsigned int *t = (unsigned int *)binary;
	unsigned int a = output1x_dcc2[4 * index + 0];
	unsigned int b = output1x_dcc2[4 * index + 1];
	unsigned int c = output1x_dcc2[4 * index + 2];
	unsigned int d = output1x_dcc2[4 * index + 3];

	if (d != t[3])
		return 0;

	if (c != t[2])
		return 0;

	if (b != t[1])
		return 0;

	return (a == t[0]);
}


static int cmp_exact(char *source, int index)
{
	// This check is for the improbable case of collisions.
	// It checks if the salts are the same.
	unsigned int *salt = fmt_mscash2.methods.salt(source);
	unsigned int i = 0;

	for(; i < 11; i++)
		if(salt[i] != salt_buffer[i])
			return 0;
	return 1;
}


static void set_key(char *_key, int index)
{
	unsigned char *key = (unsigned char *) _key;
	unsigned int md4_size = 0;
	unsigned int i = 0;
	unsigned int temp;
	unsigned int saved_base = index * SAVED_PLAIN_BUF;
	unsigned int buff_base = index << 4;

	for(; key[md4_size] && md4_size < PLAINTEXT_LENGTH; i++, md4_size++)
	{
		saved_plain[saved_base + md4_size] = key[md4_size];
		temp = key[++md4_size];
		saved_plain[saved_base + md4_size] = temp;

		if(temp)
		{
			ms_buffer1x[buff_base + i] = key[md4_size - 1] | (temp << 16);
		}
		else
		{
			ms_buffer1x[buff_base + i] = key[md4_size - 1] | 0x800000;
			goto key_cleaning;
		}
	}

	ms_buffer1x[buff_base + i] = 0x80;
	saved_plain[saved_base + md4_size] = 0;

key_cleaning:
	i++;
	for(; i <= last_i[index]; i++)
		ms_buffer1x[buff_base + i] = 0;

	last_i[index] = md4_size >> 1;

	ms_buffer1x[buff_base + 14] = md4_size << 4;

	// new password candidate
	new_key = 1;
}


static void set_key_utf8(char *_key, int index)
{
	unsigned char *key = (unsigned char *) _key;
	int utf8len = strlen(_key);
	unsigned int md4_size = 0;
	unsigned int i = 0;
	unsigned int saved_base = index * SAVED_PLAIN_BUF;
	unsigned int buff_base = index << 4;
	UTF16 utf16key[PLAINTEXT_LENGTH + 1];

	int utf16len = utf8towcs(utf16key, PLAINTEXT_LENGTH, key, utf8len);

	if (utf16len <= 0) {
		utf8len = -utf16len;
		if (utf16len != 0)
			utf16len = strlen16(utf16key);
	}

	for(;md4_size+1<utf16len;i++,md4_size+=2)
		ms_buffer1x[i+buff_base] = BESWAP16(utf16key[md4_size]) | (BESWAP16(utf16key[md4_size+1])<<16);

	if (md4_size<utf16len) {
		ms_buffer1x[i+buff_base] = 0x800000 | BESWAP16(utf16key[md4_size]);
		md4_size++;
	}
	else
		ms_buffer1x[i+buff_base]=0x80;

	for(i++;i<=last_i[index];i++)
		ms_buffer1x[i+buff_base]=0;

	last_i[index]=md4_size>>1;

	ms_buffer1x[14+buff_base] = md4_size << 4;

	memcpy(&saved_plain[saved_base], key, utf8len);
	saved_plain[saved_base+utf8len] = 0;

	//dump_stuff_msg("setkey utf8", (unsigned char*)&ms_buffer1x, 16*4);
	//{static int i;if (++i==1)exit(0);}

	// new password candidate
	new_key = 1;
}


static char *get_key(int index)
{
	return saved_plain +( index * SAVED_PLAIN_BUF);
}


// Public domain hash function by DJ Bernstein (salt is a username)
static int salt_hash(void *salt)
{
	UTF16 *s = salt;
	unsigned int hash = 5381;

	while (*s != 0x80)
		hash = ((hash << 5) + hash) ^ *s++;

	return hash & (SALT_HASH_SIZE - 1);
}


struct fmt_main fmt_mscash2 = {
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
		prepare,
		valid,
		ms_split,
		get_binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
