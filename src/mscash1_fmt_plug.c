/* MSCASH patch for john (performance improvement)
 *
 * Modified for utf-8 support by magnum in 2011, same terms as below
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2007.  No copyright
 * is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the
 * public domain is deemed null and void, then the software is
 * Copyright (c) 2007 Alain Espinosa and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"
#include "options.h"

#define FORMAT_LABEL			"mscash"
#define FORMAT_NAME			"M$ Cache Hash MD4"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		27
#define MAX_CIPHERTEXT_LENGTH		(2 + 19*3 + 1 + 32) // x3 because salt may be UTF-8 in input


/* Note: some tests will be replaced in init() if running UTF-8 */
static struct fmt_tests tests[] = {
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1" },
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1" },
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1" },
	{"176a4c2bd45ac73687676c2f09045353", "", {"root"} }, // nullstring password
	{"M$test2#ab60bdb4493822b175486810ac2abe63", "test2" },
	{"M$test3#14dd041848e12fc48c0aa7a416a4a00c", "test3" },
	{"M$test4#b945d24866af4b01a6d89b9d932a153c", "test4" },

	{"64cd29e36a8431a2b111378564a10631", "test1", {"TEST1"} },    // salt is lowercased before hashing
	{"290efa10307e36a79b3eebf2a6b29455", "okolada", {"nineteen_characters"} }, // max salt length
	{"ab60bdb4493822b175486810ac2abe63", "test2", {"test2"} },
	{"b945d24866af4b01a6d89b9d932a153c", "test4", {"test4"} },
	{NULL}
};

#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BINARY_SIZE			16
#define SALT_SIZE			(11*4)

#define OK_NUM_KEYS			64
#define BEST_NUM_KEYS			512
#ifdef _OPENMP
#define MS_NUM_KEYS			(OK_NUM_KEYS * 96)
#else
#define MS_NUM_KEYS			BEST_NUM_KEYS
#endif
#define MIN_KEYS_PER_CRYPT		OK_NUM_KEYS
#define MAX_KEYS_PER_CRYPT		MS_NUM_KEYS

static unsigned int *ms_buffer1x;
static unsigned int *output1x;
static unsigned int *crypt;
static unsigned int *last;
static unsigned int *last_i;

static unsigned int *salt_buffer;
static unsigned int new_key;

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#ifdef _OPENMP
#include <omp.h>
#endif

static void set_key_utf8(char *_key, int index);
static void set_key_encoding(char *_key, int index);
static void * get_salt_utf8(char *_ciphertext);
static void * get_salt_encoding(char *_ciphertext);
struct fmt_main fmt_mscash;

#if !ARCH_LITTLE_ENDIAN
#define ROTATE_LEFT(x, n) (x) = (((x)<<(n))|((unsigned int)(x)>>(32-(n))))
static void swap(unsigned int *x, unsigned int *y, int count)
{
	unsigned int tmp;
	do {
		tmp = *x++;
		ROTATE_LEFT(tmp, 16);
		*y++ = ((tmp & 0x00FF00FF) << 8) | ((tmp >> 8) & 0x00FF00FF);
	} while (--count);
}
#endif

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	int n = omp_get_max_threads(), nmin, nmax;
	if (n < 1)
		n = 1;
	nmin = OK_NUM_KEYS - (OK_NUM_KEYS % n);
	if (nmin < n)
		nmin = n;
	fmt_mscash.params.min_keys_per_crypt = nmin;
	nmax = n * BEST_NUM_KEYS;
	if (nmax > MS_NUM_KEYS)
		nmax = MS_NUM_KEYS;
	fmt_mscash.params.max_keys_per_crypt = nmax;
#endif

	ms_buffer1x = mem_calloc_tiny(sizeof(ms_buffer1x[0]) * 16*fmt_mscash.params.max_keys_per_crypt, MEM_ALIGN_WORD);
	output1x    = mem_calloc_tiny(sizeof(output1x[0])    *  4*fmt_mscash.params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt       = mem_calloc_tiny(sizeof(crypt[0])       *  4*fmt_mscash.params.max_keys_per_crypt, MEM_ALIGN_WORD);
	last        = mem_calloc_tiny(sizeof(last[0])        *  4*fmt_mscash.params.max_keys_per_crypt, MEM_ALIGN_WORD);
	last_i      = mem_calloc_tiny(sizeof(last_i[0])      *    fmt_mscash.params.max_keys_per_crypt, MEM_ALIGN_WORD);

	new_key=1;

	if (options.utf8) {
		fmt_mscash.methods.set_key = set_key_utf8;
		fmt_mscash.methods.salt = get_salt_utf8;
		fmt_mscash.params.plaintext_length = (PLAINTEXT_LENGTH * 3);
		tests[1].ciphertext = "M$\xC3\xBC#48f84e6f73d6d5305f6558a33fa2c9bb";
		tests[1].plaintext = "\xC3\xBC";         // German u-umlaut in UTF-8
		tests[2].ciphertext = "M$user#9121790702dda0fa5d353014c334c2ce";
		tests[2].plaintext = "\xe2\x82\xac\xe2\x82\xac"; // 2 x Euro signs
	} else if (options.ascii || options.iso8859_1) {
		tests[1].ciphertext = "M$\xFC#48f84e6f73d6d5305f6558a33fa2c9bb";
		tests[1].plaintext = "\xFC";         // German u-umlaut in UTF-8
		tests[2].ciphertext = "M$\xFC\xFC#593246a8335cf0261799bda2a2a9c623";
		tests[2].plaintext = "\xFC\xFC"; // 2 x Euro signs
	} else {
		fmt_mscash.methods.set_key = set_key_encoding;
		fmt_mscash.methods.salt = get_salt_encoding;
		fmt_mscash.params.plaintext_length = (PLAINTEXT_LENGTH * 3);
	}
}

static char * ms_split(char *ciphertext, int index)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i=0;

	for(; ciphertext[i] && i < MAX_CIPHERTEXT_LENGTH; i++)
		out[i]=ciphertext[i];

	out[i]=0;

	// lowercase salt as well as hash, encoding-aware
	enc_strlwr(&out[2]);

	return out;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	unsigned int i;
	unsigned int l;
	char insalt[3*19+1];
	UTF16 realsalt[21];
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
	saltlen = enc_to_utf16(realsalt, 20, (UTF8*)strnzcpy(insalt, &ciphertext[2], l - 2), l - 3);
	if (saltlen < 0 || saltlen > 19)
			return 0;

	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	char *cp;
	int i;
	if (!strncmp(split_fields[1], "M$", 2) || !split_fields[0])
		return split_fields[1];
	if (!split_fields[0])
		return split_fields[1];
	// ONLY check, if this string split_fields[1], is ONLY a 32 byte hex string.
	for (i = 0; i < 32; i++)
		if (atoi16[ARCH_INDEX(split_fields[1][i])] == 0x7F)
			return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 4);
	sprintf (cp, "M$%s#%s", split_fields[0], split_fields[1]);
	if (valid(cp, pFmt))
	{
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void set_salt(void *salt) {
	salt_buffer=salt;
}

static void *get_salt(char *_ciphertext)
{
	unsigned char *ciphertext = (unsigned char *)_ciphertext;
	// length=11 for save memory
	// position 10 = length
	// 0-9 = 1-19 Unicode characters + EOS marker (0x80)
	static unsigned int *out=0;
	unsigned int md4_size=0;

	if (!out) out = mem_alloc_tiny(11*sizeof(unsigned int), MEM_ALIGN_WORD);
	memset(out,0,11*sizeof(unsigned int));

	ciphertext+=2;

	for(;;md4_size++)
		if(ciphertext[md4_size]!='#' && md4_size < 19)
		{
			md4_size++;

			out[md4_size>>1] = ciphertext[md4_size-1] | ((ciphertext[md4_size]!='#') ? (ciphertext[md4_size]<<16) : 0x800000);

			if(ciphertext[md4_size]=='#')
				break;
		}
		else
		{
			out[md4_size>>1] = 0x80;
			break;
		}

	out[10] = (8 + md4_size) << 4;

//	dump_stuff(out, 44);

	return out;
}

static void *get_salt_encoding(char *_ciphertext) {
	unsigned char *ciphertext = (unsigned char *)_ciphertext;
	unsigned char input[19*3+1];
	int utf16len, md4_size;
	static UTF16 *out=0;

	if (!out) out = mem_alloc_tiny(22*sizeof(UTF16), MEM_ALIGN_WORD);
	memset(out, 0, 22*sizeof(UTF16));

	ciphertext += 2;

	for (md4_size=0;md4_size<sizeof(input)-1;md4_size++) {
		if (ciphertext[md4_size] == '#')
			break;
		input[md4_size] = ciphertext[md4_size];
	}
	input[md4_size] = 0;

	utf16len = enc_to_utf16(out, 19, input, md4_size);
	if (utf16len <= 0)
		utf16len = strlen16(out);

#if ARCH_LITTLE_ENDIAN
	out[utf16len] = 0x80;
#else
	out[utf16len] = 0x8000;
	swap((unsigned int*)out, (unsigned int*)out, (md4_size>>1)+1);
#endif

	((unsigned int*)out)[10] = (8 + utf16len) << 4;

//	dump_stuff(out, 44);

	return out;
}


static void * get_salt_utf8(char *_ciphertext)
{
	unsigned char *ciphertext = (unsigned char *)_ciphertext;
	unsigned int md4_size=0;
	UTF16 ciphertext_utf16[21];
	int len;
	static ARCH_WORD_32 *out=0;

	if (!out) out = mem_alloc_tiny(11*sizeof(ARCH_WORD_32), MEM_ALIGN_WORD);
	memset(out, 0, 11*sizeof(ARCH_WORD_32));

	ciphertext+=2;
	len = ((unsigned char*)strchr((char*)ciphertext, '#')) - ciphertext;
	utf8_to_utf16(ciphertext_utf16, 20, ciphertext, len+1);

	for(;;md4_size++) {
#if !ARCH_LITTLE_ENDIAN
		ciphertext_utf16[md4_size] = (ciphertext_utf16[md4_size]>>8)|(ciphertext_utf16[md4_size]<<8);
		ciphertext_utf16[md4_size+1] = (ciphertext_utf16[md4_size+1]>>8)|(ciphertext_utf16[md4_size+1]<<8);
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
	static union {
		unsigned long u64[BINARY_SIZE/sizeof(unsigned long)];
		unsigned int u32[BINARY_SIZE/sizeof(unsigned int)];
	} outbuf;
	unsigned int *out = (unsigned int*)outbuf.u32;
	unsigned int i=0;
	unsigned int temp;
	unsigned int *salt=fmt_mscash.methods.salt(ciphertext);

	for(;ciphertext[0]!='#';ciphertext++);

	ciphertext++;

	for(; i<4 ;i++)
	{
		temp  = (atoi16[ARCH_INDEX(ciphertext[i*8+0])])<<4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+1])]);

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+2])])<<12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+3])])<<8;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+4])])<<20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+5])])<<16;

		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+6])])<<28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i*8+7])])<<24;

		out[i]=temp;
	}

	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;

	// Reversed	b += (c ^ d ^ a) + salt_buffer[11] +  SQRT_3; b = (b << 15) | (b >> 17);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	// Reversed	c += (d ^ a ^ b) + salt_buffer[3]  +  SQRT_3; c = (c << 11) | (c >> 21);
	out[2] = (out[2] << 21) | (out[2] >> 11);
	out[2]-= SQRT_3 + (out[3] ^ out[0] ^ out[1]) + salt[3];
	// Reversed	d += (a ^ b ^ c) + salt_buffer[7]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
	out[3]  = (out[3] << 23) | (out[3] >> 9);
	out[3] -= SQRT_3 + (out[0] ^ out[1] ^ out[2]) + salt[7];
	//+ SQRT_3; d = (d << 9 ) | (d >> 23);
	out[3]=(out[3] << 23 ) | (out[3] >> 9);
	out[3]-=SQRT_3;

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
	return output1x[4*index+3] & 0x0F;
}

static int get_hash_1(int index)
{
	return output1x[4*index+3] & 0xFF;
}

static int get_hash_2(int index)
{
	return output1x[4*index+3] & 0x0FFF;
}

static int get_hash_3(int index)
{
	return output1x[4*index+3] & 0x0FFFF;
}

static int get_hash_4(int index)
{
	return output1x[4*index+3] & 0x0FFFFF;
}

static void nt_hash(int count)
{
	int i;

#if MS_NUM_KEYS > 1 && defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, ms_buffer1x, crypt, last)
#endif
	for (i = 0; i < count; i++)
	{
		unsigned int a;
		unsigned int b;
		unsigned int c;
		unsigned int d;

		/* Round 1 */
		a = 		0xFFFFFFFF 		  + ms_buffer1x[16*i+0];a = (a << 3 ) | (a >> 29);
		d = INIT_D + (INIT_C ^ (a & 0x77777777))  + ms_buffer1x[16*i+1];d = (d << 7 ) | (d >> 25);
		c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B)))+ ms_buffer1x[16*i+2];c = (c << 11) | (c >> 21);
		b =    INIT_B + (a ^ (c & (d ^ a))) 	  + ms_buffer1x[16*i+3];b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16*i+4]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16*i+5]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16*i+6]  ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a))) + ms_buffer1x[16*i+7]  ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16*i+8]  ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16*i+9]  ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16*i+10] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a))) + ms_buffer1x[16*i+11] ;b = (b << 19) | (b >> 13);

		a += (d ^ (b & (c ^ d))) + ms_buffer1x[16*i+12] ;a = (a << 3 ) | (a >> 29);
		d += (c ^ (a & (b ^ c))) + ms_buffer1x[16*i+13] ;d = (d << 7 ) | (d >> 25);
		c += (b ^ (d & (a ^ b))) + ms_buffer1x[16*i+14] ;c = (c << 11) | (c >> 21);
		b += (a ^ (c & (d ^ a)))/*+ms_buffer1x[16*i+15]*/;b = (b << 19) | (b >> 13);

		/* Round 2 */
		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+0]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+4]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+8]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16*i+12] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+1]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+5]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+9]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16*i+13] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+2]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+6]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+10] + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a)) + ms_buffer1x[16*i+14] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d)) + ms_buffer1x[16*i+3]  + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c)) + ms_buffer1x[16*i+7]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b)) + ms_buffer1x[16*i+11] + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))/*+ms_buffer1x[16*i+15]*/+SQRT_2; b = (b << 13) | (b >> 19);

		/* Round 3 */
		a += (b ^ c ^ d) + ms_buffer1x[16*i+0]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+8]  + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+4]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16*i+12] + SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + ms_buffer1x[16*i+2]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+10] + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+6]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16*i+14] + SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + ms_buffer1x[16*i+1]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+9]  + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+5]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + ms_buffer1x[16*i+13] + SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + ms_buffer1x[16*i+3]  + SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + ms_buffer1x[16*i+11] + SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + ms_buffer1x[16*i+7]  + SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) /*+ ms_buffer1x[16*i+15] */+ SQRT_3; b = (b << 15) | (b >> 17);

		crypt[4*i+0] = a + INIT_A;
		crypt[4*i+1] = b + INIT_B;
		crypt[4*i+2] = c + INIT_C;
		crypt[4*i+3] = d + INIT_D;

		//Another MD4_crypt for the salt
		/* Round 1 */
		a= 	        0xFFFFFFFF 	            +crypt[4*i+0]; a=(a<<3 )|(a>>29);
		d=INIT_D + ( INIT_C ^ ( a & 0x77777777))    +crypt[4*i+1]; d=(d<<7 )|(d>>25);
		c=INIT_C + ( INIT_B ^ ( d & ( a ^ INIT_B))) +crypt[4*i+2]; c=(c<<11)|(c>>21);
		b=INIT_B + (    a   ^ ( c & ( d ^    a  ))) +crypt[4*i+3]; b=(b<<19)|(b>>13);

		last[4*i+0]=a;
		last[4*i+1]=b;
		last[4*i+2]=c;
		last[4*i+3]=d;
	}
}

static void crypt_all(int count)
{
	int i;

	if(new_key)
	{
		new_key=0;
		nt_hash(count);
	}

#if MS_NUM_KEYS > 1 && defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, last, crypt, salt_buffer, output1x)
#endif
	for(i = 0; i < count; i++)
	{
		unsigned int a;
		unsigned int b;
		unsigned int c;
		unsigned int d;

		a = last[4*i+0];
		b = last[4*i+1];
		c = last[4*i+2];
		d = last[4*i+3];

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

		/* Round 2 */
		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+0]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[0]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[4]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[8]  + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+1]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[1]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[5]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[9]  + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+2]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[2]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[6]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[10] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt[4*i+3]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[3]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[7]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))/*+ salt_buffer[11]*/+ SQRT_2; b = (b << 13) | (b >> 19);

		/* Round 3 */
		a += (b ^ c ^ d) + crypt[4*i+0]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[4]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[0]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[8]  +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + crypt[4*i+2]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[6]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[2]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[10] +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + crypt[4*i+1]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[5];

		output1x[4*i+0]=a;
		output1x[4*i+1]=b;
		output1x[4*i+2]=c;
		output1x[4*i+3]=d;
	}
}

static int cmp_all(void *binary, int count)
{
	unsigned int i=0;
	unsigned int d=((unsigned int *)binary)[3];

	for(;i<count;i++)
		if(d==output1x[i*4+3])
			return 1;

	return 0;
}

static int cmp_one(void * binary, int index)
{
	unsigned int *t=(unsigned int *)binary;
	unsigned int a=output1x[4*index+0];
	unsigned int b=output1x[4*index+1];
	unsigned int c=output1x[4*index+2];
	unsigned int d=output1x[4*index+3];

	if(d!=t[3])
		return 0;
	d+=SQRT_3;d = (d << 9 ) | (d >> 23);

	c += (d ^ a ^ b) + salt_buffer[1]  +  SQRT_3; c = (c << 11) | (c >> 21);
	if(c!=t[2])
		return 0;

	b += (c ^ d ^ a) + salt_buffer[9]  +  SQRT_3; b = (b << 15) | (b >> 17);
	if(b!=t[1])
		return 0;

	a += (b ^ c ^ d) + crypt[4*index+3]+  SQRT_3; a = (a << 3 ) | (a >> 29);
	return (a==t[0]);
}

static int cmp_exact(char *source, int index)
{
	// This check its for the unreal case of collisions.
	// It verify that the salts its the same.
	unsigned int *salt=fmt_mscash.methods.salt(source);
	unsigned int i=0;
	for(;i<11;i++)
		if(salt[i]!=salt_buffer[i])
			return 0;
	return 1;
}

// This is common code for the SSE/MMX/generic variants of non-UTF8 set_key
static inline void set_key_helper(unsigned int * keybuffer,
                                  unsigned int xBuf,
                                  const unsigned char * key,
                                  unsigned int lenStoreOffset,
                                  unsigned int *last_length)
{
	unsigned int i=0;
	unsigned int md4_size=0;
	for(; key[md4_size] && md4_size < PLAINTEXT_LENGTH; i += xBuf, md4_size++)
	{
		unsigned int temp;
		if ((temp = key[++md4_size]))
		{
			keybuffer[i] = key[md4_size-1] | (temp << 16);
		}
		else
		{
			keybuffer[i] = key[md4_size-1] | 0x800000;
			goto key_cleaning;
		}
	}
	keybuffer[i] = 0x80;

key_cleaning:
	i += xBuf;
	for(;i <= *last_length; i += xBuf)
		keybuffer[i] = 0;

	*last_length = (md4_size >> 1)+1;

	keybuffer[lenStoreOffset] = md4_size << 4;
}

static void set_key(char *_key, int index)
{
	set_key_helper(&ms_buffer1x[index << 4], 1, (unsigned char *)_key, 14,
	               &last_i[index]);
	//new password_candidate
	new_key=1;

//	printf ("\n");
//	dump_stuff(ms_buffer1x, 64);

//dump_stuff_msg("setkey     ", (unsigned char*)&ms_buffer1x[index << 4], 40);
//{static int i;if (++i==1)exit(0);}
}

// UTF-8 conversion right into key buffer
// This is common code for the SSE/MMX/generic variants
static inline void set_key_helper_utf8(unsigned int * keybuffer, unsigned int xBuf,
    const UTF8 * source, unsigned int lenStoreOffset, unsigned int *lastlen)
{
	unsigned int *target = keybuffer;
	unsigned int *targetEnd = &keybuffer[xBuf * ((PLAINTEXT_LENGTH + 1) >> 1)];
	UTF32 chl, chh = 0x80;
	unsigned int outlen = 0;

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
				} else {
					*lastlen = ((27 >> 1) + 1) * xBuf;
					return;
				}
			case 1:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else {
					*lastlen = ((27 >> 1) + 1) * xBuf;
					return;
				}
			case 0:
				break;
			default:
				*lastlen = ((27 >> 1) + 1) * xBuf;
				return;
			}
			chl -= offsetsFromUTF8[extraBytesToRead];
		}
		source++;
		outlen++;
		if (*source) {
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
					} else {
						*lastlen = ((27 >> 1) + 1) * xBuf;
						return;
					}
				case 1:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else {
						*lastlen = ((27 >> 1) + 1) * xBuf;
						return;
					}
				case 0:
					break;
				default:
					*lastlen = ((27 >> 1) + 1) * xBuf;
					return;
				}
				chh -= offsetsFromUTF8[extraBytesToRead];
			}
			source++;
			outlen++;
		} else {
			chh = 0x80;
		}
		*target = chh << 16 | chl;
		target += xBuf;
		if (*source == 0) {
			break;
		}
		if (target >= targetEnd) {
			break;
		}
	}
	if (chh != 0x80 || outlen == 0) {
		*target = 0x80;
		target += xBuf;
	}

	while(target < &keybuffer[*lastlen]) {
		*target = 0;
		target += xBuf;
	}

	*lastlen = ((outlen >> 1) + 1) * xBuf;
	keybuffer[lenStoreOffset] = outlen << 4;
}

static void set_key_utf8(char *_key, int index)
{
	set_key_helper_utf8(&ms_buffer1x[index << 4], 1, (UTF8 *)_key, 14,
	                &last_i[index]);
	//new password_candidate
	new_key=1;

//dump_stuff_msg("setkey utf8", (unsigned char*)&ms_buffer1x[index << 4], 40);
//{static int i;if (++i==1)exit(0);}
}

// This is common code for the SSE/MMX/generic variants of non-UTF8 non-ISO-8859-1 set_key
static inline void set_key_helper_encoding(unsigned int * keybuffer,
                                  unsigned int xBuf,
                                  const unsigned char * key,
                                  unsigned int lenStoreOffset,
                                  unsigned int *last_length)
{
	unsigned int i=0;
	int md4_size;
	md4_size = enc_to_utf16( (UTF16 *)keybuffer, PLAINTEXT_LENGTH, (UTF8 *) key, strlen((char*)key));
	if (md4_size < 0)
		md4_size = strlen16((UTF16 *)keybuffer);

#if ARCH_LITTLE_ENDIAN
	((UTF16*)keybuffer)[md4_size] = 0x80;
#else
	((UTF16*)keybuffer)[md4_size] = 0x8000;
#endif
	((UTF16*)keybuffer)[md4_size+1] = 0;
#if !ARCH_LITTLE_ENDIAN
	((UTF16*)keybuffer)[md4_size+2] = 0;
#endif
	i = md4_size>>1;

	i += xBuf;
	for(;i <= *last_length; i += xBuf)
		keybuffer[i] = 0;

#if !ARCH_LITTLE_ENDIAN
	swap(keybuffer, keybuffer, (md4_size>>1)+1);
#endif

	*last_length = (md4_size >> 1) + 1;

	keybuffer[lenStoreOffset] = md4_size << 4;
}

static void set_key_encoding(char *_key, int index)
{
	set_key_helper_encoding(&ms_buffer1x[index << 4], 1, (unsigned char *)_key, 14,
	               &last_i[index]);
	//new password_candidate
	new_key=1;

//	printf ("\n");
//	dump_stuff(ms_buffer1x, 64);

//dump_stuff_msg("setkey     ", (unsigned char*)&ms_buffer1x[index << 4], 40);
//{static int i;if (++i==1)exit(0);}
}


// Get the key back from the key buffer, from UCS-2
// This is common code for the SSE/MMX/generic variants
static inline UTF16 *get_key_helper(unsigned int * keybuffer, unsigned int xBuf)
{
	static UTF16 key[PLAINTEXT_LENGTH + 1];
	unsigned int md4_size=0;
	unsigned int i=0;

	for(; md4_size < PLAINTEXT_LENGTH; i += xBuf, md4_size++)
	{
		key[md4_size] = keybuffer[i];
		key[md4_size+1] = keybuffer[i] >> 16;
		if (key[md4_size] == 0x80 && key[md4_size+1] == 0) {
			key[md4_size] = 0;
			break;
		}
		++md4_size;
		if (key[md4_size] == 0x80 && ((keybuffer[i+xBuf]&0xFFFF) == 0 || md4_size == PLAINTEXT_LENGTH)) {
			key[md4_size] = 0;
			break;
		}
	}
	return key;
}

static char *get_key(int index)
{
	return (char *)utf16_to_enc(get_key_helper(&ms_buffer1x[index << 4], 1));
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

struct fmt_main fmt_mscash = {
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
