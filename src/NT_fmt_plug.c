/* NTLM patch for john (performance improvement)
 *
 * Written by Alain Espinosa <alainesp at gmail.com> in 2007 and
 * modified by magnum in 2011.  No copyright is claimed, and the
 * software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2007 Alain Espinosa
 * Copyright (c) 2011 magnum
 * and it is hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * (This is a heavily cut-down "BSD license".)
 *
 */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"

//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1


#define FORMAT_LABEL			"nt"
#define FORMAT_NAME			"NT MD4"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		27
#define CIPHERTEXT_LENGTH		36

// Note: the ISO-8859-1 plaintexts will be replaced in init() if running UTF-8
static struct fmt_tests tests[] = {
	{"$NT$b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{"$NT$7a21990fcd3d759941e45c490f143d5f", "12345"},
	{"$NT$f9e37e83b83c47a93c2f09f66408631b", "abc123"},
	{"$NT$8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"$NT$2b2ac2d1c7c8fda6cea80b5fad7563aa", "computer"},
	{"$NT$32ed87bdb5fdc5e9cba88547376818d4", "123456"},
	{"$NT$b7e0ea9fbffcf6dd83086e905089effd", "tigger"},
	{"$NT$7ce21f17c0aee7fb9ceba532d0546ad6", "1234"},
	{"$NT$b23a90d0aad9da3615fafc27a1b8baeb", "a1b2c3"},
	{"$NT$2d20d252a479f485cdf5e171d93985bf", "qwerty"},
	{"$NT$3dbde697d71690a769204beb12283678", "123"},
	{"$NT$c889c75b7c1aae1f7150c5681136e70e", "xxx"},
	{"$NT$d5173c778e0f56d9fc47e3b3c829aca7", "money"},
	{"$NT$0cb6948805f797bf2a82807973b89537", "test"},
	{"$NT$0569fcf2b14b9c7f3d3b5f080cbd85e5", "carmen"},
	{"$NT$f09ab1733a528f430353834152c8a90e", "mickey"},
	{"$NT$878d8014606cda29677a44efa1353fc7", "secret"},
	{"$NT$85ac333bbfcbaa62ba9f8afb76f06268", "summer"},
	{"$NT$5962cc080506d90be8943118f968e164", "internet"},
	{"$NT$f07206c3869bda5acd38a3d923a95d2a", "service"},
	{"$NT$d0dfc65e8f286ef82f6b172789a0ae1c", "canada"},
	{"$NT$066ddfd4ef0e9cd7c256fe77191ef43c", "hello"},
	{"$NT$39b8620e745b8aa4d1108e22f74f29e2", "ranger"},
	{"$NT$8d4ef8654a9adc66d4f628e94f66e31b", "shadow"},
	{"$NT$320a78179516c385e35a93ffa0b1c4ac", "baseball"},
	{"$NT$e533d171ac592a4e70498a58b854717c", "donald"},
	{"$NT$5eee54ce19b97c11fd02e531dd268b4c", "harley"},
	{"$NT$6241f038703cbfb7cc837e3ee04f0f6b", "hockey"},
	{"$NT$becedb42ec3c5c7f965255338be4453c", "letmein"},
	{"$NT$ec2c9f3346af1fb8e4ee94f286bac5ad", "maggie"},
	{"$NT$f5794cbd75cf43d1eb21fad565c7e21c", "mike"},
	{"$NT$74ed32086b1317b742c3a92148df1019", "mustang"},
	{"$NT$63af6e1f1dd9ecd82f17d37881cb92e6", "snoopy"},
	{"$NT$58def5844fe58e8f26a65fff9deb3827", "buster"},
	{"$NT$f7eb9c06fafaa23c4bcf22ba6781c1e2", "dragon"},
	{"$NT$dd555241a4321657e8b827a40b67dd4a", "jordan"},
	{"$NT$bb53a477af18526ada697ce2e51f76b3", "michael"},
	{"$NT$92b7b06bb313bf666640c5a1e75e0c18", "michelle"},
	{NULL}
};

#define BINARY_SIZE			16
#define SALT_SIZE			0

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

#if defined (NT_X86_64)
	#define NT_NUM_KEYS	32

#ifdef _MSC_VER
	__declspec(align(16)) unsigned int nt_buffer8x[16*NT_NUM_KEYS];
	__declspec(align(16)) unsigned int output8x[4*NT_NUM_KEYS];
#else
	unsigned int nt_buffer8x[16*NT_NUM_KEYS] __attribute__ ((aligned(16)));
	unsigned int output8x[4*NT_NUM_KEYS] __attribute__ ((aligned(16)));
#endif

	#define ALGORITHM_NAME		"128/128 X2 SSE2-16"
	#define NT_CRYPT_FUN		nt_crypt_all_x86_64
	extern void nt_crypt_all_x86_64(int count);
	extern void nt_crypt_all_8859_1_x86_64(int count);
#elif defined (NT_SSE2)
	#define NT_NUM_KEYS	40
	#define NT_NUM_KEYS1	8
	#define NT_NUM_KEYS4	32

#ifdef _MSC_VER
	__declspec(align(16)) unsigned int nt_buffer4x[64*NT_NUM_KEYS1];
	__declspec(align(16)) unsigned int output4x[16*NT_NUM_KEYS1];
#else
	unsigned int nt_buffer4x[64*NT_NUM_KEYS1] __attribute__ ((aligned(16)));
	unsigned int output4x[16*NT_NUM_KEYS1] __attribute__ ((aligned(16)));
#endif

	unsigned int nt_buffer1x[16*NT_NUM_KEYS1];
	unsigned int output1x[4*NT_NUM_KEYS1];

	#define ALGORITHM_NAME		"128/128 SSE2 + 32/32"
	#define NT_CRYPT_FUN		nt_crypt_all_sse2
	extern void nt_crypt_all_sse2(int count);
#else
	#define NT_NUM_KEYS		64
	unsigned int nt_buffer1x[16*NT_NUM_KEYS];
	unsigned int output1x[4*NT_NUM_KEYS];

	#define ALGORITHM_NAME		"32/32"
	#define NT_CRYPT_FUN		nt_crypt_all_generic
	static void nt_crypt_all_generic(int count)
	{
		unsigned int a;
		unsigned int b;
		unsigned int c;
		unsigned int d;
		unsigned int i=0;

		for(;i<NT_NUM_KEYS;i++)
		{
			/* Round 1 */
			a = 		0xFFFFFFFF 		 +nt_buffer1x[i*16+0];a=(a<<3 )|(a>>29);
			d = INIT_D+(INIT_C ^ (a & 0x77777777))   +nt_buffer1x[i*16+1];d=(d<<7 )|(d>>25);
			c = INIT_C+(INIT_B ^ (d & (a ^ INIT_B))) +nt_buffer1x[i*16+2];c=(c<<11)|(c>>21);
			b = INIT_B + (a ^ (c & (d ^ a))) 	 +nt_buffer1x[i*16+3];b=(b<<19)|(b>>13);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer1x[i*16+4]  ;a = (a << 3 ) | (a >> 29);
			d += (c ^ (a & (b ^ c)))  +  nt_buffer1x[i*16+5]  ;d = (d << 7 ) | (d >> 25);
			c += (b ^ (d & (a ^ b)))  +  nt_buffer1x[i*16+6]  ;c = (c << 11) | (c >> 21);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer1x[i*16+7]  ;b = (b << 19) | (b >> 13);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer1x[i*16+8]  ;a = (a << 3 ) | (a >> 29);
			d += (c ^ (a & (b ^ c)))  +  nt_buffer1x[i*16+9]  ;d = (d << 7 ) | (d >> 25);
			c += (b ^ (d & (a ^ b)))  +  nt_buffer1x[i*16+10] ;c = (c << 11) | (c >> 21);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer1x[i*16+11] ;b = (b << 19) | (b >> 13);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer1x[i*16+12] ;a = (a << 3 ) | (a >> 29);
			d += (c ^ (a & (b ^ c)))  +  nt_buffer1x[i*16+13] ;d = (d << 7 ) | (d >> 25);
			c += (b ^ (d & (a ^ b)))  +  nt_buffer1x[i*16+14] ;c = (c << 11) | (c >> 21);
			b += (a ^ (c & (d ^ a)));b = (b << 19) | (b >> 13);

			/* Round 2 */
			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+0] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+4] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+8] +SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))+nt_buffer1x[i*16+12]+SQRT_2;b = (b<<13) | (b>>19);

			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+1] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+5] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+9] +SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))+nt_buffer1x[i*16+13]+SQRT_2;b = (b<<13) | (b>>19);

			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+2] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+6] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+10]+SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))+nt_buffer1x[i*16+14]+SQRT_2;b = (b<<13) | (b>>19);

			a += ((b & (c | d)) | (c & d))+nt_buffer1x[i*16+3] +SQRT_2;a = (a<<3 ) | (a>>29);
			d += ((a & (b | c)) | (b & c))+nt_buffer1x[i*16+7] +SQRT_2;d = (d<<5 ) | (d>>27);
			c += ((d & (a | b)) | (a & b))+nt_buffer1x[i*16+11]+SQRT_2;c = (c<<9 ) | (c>>23);
			b += ((c & (d | a)) | (d & a))			   +SQRT_2;b = (b<<13) | (b>>19);

			/* Round 3 */
			a += (d ^ c ^ b) + nt_buffer1x[i*16+0]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
			d += (c ^ b ^ a) + nt_buffer1x[i*16+8]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
			c += (b ^ a ^ d) + nt_buffer1x[i*16+4]  +  SQRT_3; c = (c << 11) | (c >> 21);
			b += (a ^ d ^ c) + nt_buffer1x[i*16+12] +  SQRT_3; b = (b << 15) | (b >> 17);

			a += (d ^ c ^ b) + nt_buffer1x[i*16+2]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
			d += (c ^ b ^ a) + nt_buffer1x[i*16+10] +  SQRT_3; d = (d << 9 ) | (d >> 23);
			c += (b ^ a ^ d) + nt_buffer1x[i*16+6]  +  SQRT_3; c = (c << 11) | (c >> 21);
			b += (a ^ d ^ c) + nt_buffer1x[i*16+14] +  SQRT_3; b = (b << 15) | (b >> 17);

			a += (d ^ c ^ b) + nt_buffer1x[i*16+1]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
			d += (c ^ b ^ a) + nt_buffer1x[i*16+9]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
			c += (b ^ a ^ d) + nt_buffer1x[i*16+5]  +  SQRT_3; c = (c << 11) | (c >> 21);
			b += (a ^ d ^ c) + nt_buffer1x[i*16+13];

			output1x[4*i+0]=a;
			output1x[4*i+1]=b;
			output1x[4*i+2]=c;
			output1x[4*i+3]=d;
		}
	}
#endif

static unsigned int last_i[NT_NUM_KEYS];

#define MIN_KEYS_PER_CRYPT		NT_NUM_KEYS
#define MAX_KEYS_PER_CRYPT		NT_NUM_KEYS

static void set_key_utf8(char *_key, int index);
static void set_key_encoding(char *_key, int index);
extern struct fmt_main fmt_NT;

static void fmt_NT_init(struct fmt_main *pFmt)
{
	memset(last_i,0,4*NT_NUM_KEYS);
#if defined(NT_X86_64)
	memset(nt_buffer8x,0,16*4*NT_NUM_KEYS);
#elif defined(NT_SSE2)
	memset(nt_buffer4x,0,64*4*NT_NUM_KEYS1);
	memset(nt_buffer1x,0,16*4*NT_NUM_KEYS1);
#else
	memset(nt_buffer1x,0,16*4*NT_NUM_KEYS);
#endif
	if (options.utf8) {
#if defined (NT_X86_64)
		fmt_NT.methods.crypt_all = nt_crypt_all_x86_64;
#endif
		/* This avoids an if clause for every set_key */
		fmt_NT.methods.set_key = set_key_utf8;
		/* kick it up from 27. We will 'adjust' in the setkey_utf8 function.  */
		fmt_NT.params.plaintext_length = 3 * PLAINTEXT_LENGTH;
		tests[1].plaintext = "\xC3\xBC";         // German u-umlaut in UTF-8
		tests[1].ciphertext = "$NT$8bd6e4fb88e01009818749c5443ea712";
		tests[2].plaintext = "\xC3\xBC\xC3\xBC"; // two of them
		tests[2].ciphertext = "$NT$cc1260adb6985ca749f150c7e0b22063";
		tests[3].plaintext = "\xE2\x82\xAC";     // euro sign
		tests[3].ciphertext = "$NT$030926b781938db4365d46adc7cfbcb8";
		tests[4].plaintext = "\xE2\x82\xAC\xE2\x82\xAC";
		tests[4].ciphertext = "$NT$682467b963bb4e61943e170a04f7db46";
	} else {
		if (options.ascii || options.iso8859_1) {
#if defined (NT_X86_64)
			fmt_NT.methods.crypt_all = nt_crypt_all_8859_1_x86_64;
#endif
		} else {
			fmt_NT.methods.set_key = set_key_encoding;
		}
		if (CP_to_Unicode[0xfc] == 0x00fc) {
			tests[1].plaintext = "\xFC";         // German u-umlaut in UTF-8
			tests[1].ciphertext = "$NT$8bd6e4fb88e01009818749c5443ea712";
			tests[2].plaintext = "\xFC\xFC"; // two of them
			tests[2].ciphertext = "$NT$cc1260adb6985ca749f150c7e0b22063";
			tests[3].plaintext = "\xFC\xFC\xFC";     // 3 of them
			tests[3].ciphertext = "$NT$2e583e8c210fb101994c19877ac53b89";
			tests[4].plaintext = "\xFC\xFC\xFC\xFC";
			tests[4].ciphertext = "$NT$243bb98e7704797f92b1dd7ded6da0d0";
		}
	}
}

static char * nt_split(char *ciphertext, int index)
{
	static char out[37];

	if (!strncmp(ciphertext, "$NT$", 4))
		ciphertext += 4;

	out[0] = '$';
	out[1] = 'N';
	out[2] = 'T';
	out[3] = '$';

	memcpy(&out[4], ciphertext, 32);
	out[36] = 0;

	strlwr(&out[4]);

	return out;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos;

	if (strncmp(ciphertext, "$NT$", 4)!=0) return 0;

        for (pos = &ciphertext[4]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

        if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
        else
        	return 0;

}

// here to 'handle' the pwdump files:  user:uid:lmhash:ntlmhash:::
// Note, we address the user id inside loader.
static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	static char out[33+5];
	extern struct options_main options;
	if (!valid(split_fields[1], pFmt)) {
		if (split_fields[3] && strlen(split_fields[3]) == 32) {
			sprintf(out, "$NT$%s", split_fields[3]);
			if (valid(out,pFmt))
				return out;
		}
		if (options.format && !strcmp(options.format, "nt") && strlen(split_fields[1]) == 32) {
			sprintf(out, "$NT$%s", split_fields[1]);
			if (valid(out,pFmt))
				return out;
		}
	}
	return split_fields[1];
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned long u64[16/sizeof(unsigned long)];
		unsigned int u32[16/sizeof(unsigned int)];
	} outbuf;
	unsigned int *out = (unsigned int*)outbuf.u32;
	unsigned int i=0;
	unsigned int temp;

	ciphertext+=4;
	for (; i<4; i++)
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

	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3;

	return out;
}

static int binary_hash_0(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x0F;
}

static int binary_hash_1(void *binary)
{
	return ((unsigned int *)binary)[1] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x0FFF;
}

static int binary_hash_3(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x0FFFF;
}

static int binary_hash_4(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x0FFFFF;
}

static int binary_hash_5(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x0FFFFFF;
}

static int binary_hash_6(void *binary)
{
	return ((unsigned int *)binary)[1] & 0x07FFFFFF;
}

static int get_hash_0(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x0F;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x0F;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x0F;
#else
	return output1x[(index<<2)+1] & 0x0F;
#endif
}

static int get_hash_1(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0xFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0xFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0xFF;
#else
	return output1x[(index<<2)+1] & 0xFF;
#endif
}

static int get_hash_2(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x0FFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x0FFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x0FFF;
#else
	return output1x[(index<<2)+1] & 0x0FFF;
#endif
}

static int get_hash_3(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x0FFFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x0FFFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x0FFFF;
#else
	return output1x[(index<<2)+1] & 0x0FFFF;
#endif
}

static int get_hash_4(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x0FFFFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x0FFFFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x0FFFFF;
#else
	return output1x[(index<<2)+1] & 0x0FFFFF;
#endif
}

static int get_hash_5(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x0FFFFFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x0FFFFFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x0FFFFFF;
#else
	return output1x[(index<<2)+1] & 0x0FFFFFF;
#endif
}

static int get_hash_6(int index)
{
#if defined(NT_X86_64)
	return output8x[32*(index>>3)+8+index%8] & 0x07FFFFFF;
#elif defined(NT_SSE2)
	if(index<NT_NUM_KEYS4)
		return output4x[16*(index>>2)+4+index%4] & 0x07FFFFFF;
	else
		return output1x[(index-NT_NUM_KEYS4)*4+1] & 0x07FFFFFF;
#else
	return output1x[(index<<2)+1] & 0x07FFFFFF;
#endif
}

static int cmp_all(void *binary, int count)
{
	unsigned int i=0;
	unsigned int b=((unsigned int *)binary)[1];

#if defined(NT_X86_64)
	for(;i<(NT_NUM_KEYS/8);i++)
		if(b==output8x[i*32+8] || b==output8x[i*32+9] || b==output8x[i*32+10] || b==output8x[i*32+11] || b==output8x[i*32+12] || b==output8x[i*32+13] || b==output8x[i*32+14] || b==output8x[i*32+15])
			return 1;
#elif defined(NT_SSE2)
	unsigned int pos=4;

	for(;i<NT_NUM_KEYS1;i++,pos+=16)
		if(b==output4x[pos] || b==output4x[pos+1] || b==output4x[pos+2] || b==output4x[pos+3])
			return 1;
	i=1;
	for(;i<NT_NUM_KEYS4;i+=4)
		if(b==output1x[i])
			return 1;
#else
	for(;i<NT_NUM_KEYS;i++)
		if(b==output1x[i*4+1])
			return 1;
#endif

	return 0;
}

static int cmp_one(void * binary, int index)
{
	unsigned int *t=(unsigned int *)binary;
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;

	unsigned int * buffer;
	int pos1;
	int pos2;
	int pos3;

#if defined(NT_X86_64)
	int temp;
	buffer=nt_buffer8x;

	temp=32*(index>>3)+index%8;

	a=output8x[temp];
	b=output8x[temp+8];
	c=output8x[temp+16];
	d=output8x[temp+24];

	pos1=24+index%8+128*(index>>3);
	pos2=64+pos1;
	pos3=32+pos1;
#elif defined(NT_SSE2)
	int temp;

	if(index<NT_NUM_KEYS4)
	{
		buffer=nt_buffer4x;

		temp=16*(index>>2)+index%4;

		a=output4x[temp];
		b=output4x[temp+4];
		c=output4x[temp+8];
		d=output4x[temp+12];

		pos1=12+index%4+64*(index>>2);
		pos2=32+pos1;
		pos3=16+pos1;
	}
	else
	{
		buffer=nt_buffer1x;

		temp=4*(index-NT_NUM_KEYS4);

		a=output1x[temp];
		b=output1x[temp+1];
		c=output1x[temp+2];
		d=output1x[temp+3];

		pos1=3+4*temp;
		pos2=8+pos1;
		pos3=4+pos1;
	}
#else
	buffer=nt_buffer1x;

	a=output1x[(index<<2)];
	b=output1x[(index<<2)+1];
	c=output1x[(index<<2)+2];
	d=output1x[(index<<2)+3];

	pos1=(index<<4)+3;
	pos2=8+pos1;
	pos3=4+pos1;
#endif
	if(b!=t[1])
		return 0;
	b += SQRT_3;b = (b << 15) | (b >> 17);

	a += (b ^ c ^ d) + buffer[pos1] + SQRT_3; a = (a << 3 ) | (a >> 29);
	if(a!=t[0])
		return 0;

	d += (a ^ b ^ c) + buffer[pos2] + SQRT_3; d = (d << 9 ) | (d >> 23);
	if(d!=t[3])
		return 0;

	c += (d ^ a ^ b) + buffer[pos3] + SQRT_3; c = (c << 11) | (c >> 21);
	return c==t[2];
}

static int cmp_exact(char *source, int index)
{
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
	for(; key[md4_size]; i += xBuf, md4_size++)
	{
		unsigned int temp;
		if ((temp = key[++md4_size]) && md4_size < PLAINTEXT_LENGTH)
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

	if (xBuf==1)
		*last_length = (md4_size >> 1) + 1;
	else
		*last_length = md4_size << (xBuf>>2);

	keybuffer[lenStoreOffset] = md4_size << 4;
}

static void set_key(char *_key, int index)
{
#if defined(NT_X86_64)
	set_key_helper(&nt_buffer8x[128 * (index >> 3) + index % 8], 8,
	               (unsigned char *)_key, 112, &last_i[index]);
#elif defined(NT_SSE2)
	if(index < NT_NUM_KEYS4) {
		set_key_helper(&nt_buffer4x[64 * (index >> 2) + index % 4], 4,
		               (unsigned char *)_key, 56, &last_i[index]);
	}
	else
		set_key_helper(&nt_buffer1x[16 * (index - NT_NUM_KEYS4)], 1,
		               (unsigned char *)_key, 14, &last_i[index]);
#else
	set_key_helper(&nt_buffer1x[index << 4], 1, (unsigned char *)_key, 14,
	               &last_i[index]);
//	dump_stuff_msg("setkey ", (unsigned char*)&nt_buffer1x[index << 4], 64);
//	exit(0);
#endif
}

// UTF-8 conversion right into key buffer
// This is common code for the SSE/MMX/generic variants
static inline void set_key_helper_utf8(unsigned int * keybuffer, unsigned int xBuf,
    const UTF8 * source, unsigned int lenStoreOffset, unsigned int *lastlen)
{
	unsigned int *target = keybuffer;
	unsigned int *targetEnd = &keybuffer[xBuf * (PLAINTEXT_LENGTH >> 1)];
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
		if (*source && (target < targetEnd)) {
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
			*target = chh << 16 | chl;
			target += xBuf;
			break;
		}
		*target = chh << 16 | chl;
		target += xBuf;
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
#if defined(NT_X86_64)
	set_key_helper_utf8(&nt_buffer8x[128 * (index >> 3) + index % 8], 8,
	                (UTF8 *)_key, 112, &last_i[index]);
#elif defined(NT_SSE2)
	if(index < NT_NUM_KEYS4)
		set_key_helper_utf8(&nt_buffer4x[64 * (index >> 2) + index % 4], 4,
		                (UTF8 *)_key, 56, &last_i[index]);
	else
		set_key_helper_utf8(&nt_buffer1x[16 * (index - NT_NUM_KEYS4)], 1,
		                (UTF8 *)_key, 14, &last_i[index]);
#else
	set_key_helper_utf8(&nt_buffer1x[index << 4], 1, (UTF8 *)_key, 14,
	                &last_i[index]);
//	dump_stuff_msg("setkey utf8 ", (unsigned char*)&nt_buffer1x[index << 4], 40);
//	exit(0);
#endif
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
	if (xBuf == 1) {
		md4_size = enc_to_utf16( (UTF16 *)keybuffer, PLAINTEXT_LENGTH, (UTF8 *) key, strlen((char*)key));
		if (md4_size < 0)
			md4_size = strlen16((UTF16 *)keybuffer);
#if ARCH_LITTLE_ENDIAN
		((UTF16*)keybuffer)[md4_size] = 0x80;
#else
		((UTF16*)keybuffer)[md4_size] = 0x8000;
		((UTF16*)keybuffer)[md4_size+2] = 0;
#endif
		((UTF16*)keybuffer)[md4_size+1] = 0;
		i = md4_size>>1;
	} else {
		unsigned int temp;
		i = 0;
		for(md4_size = 0; key[md4_size]; i += xBuf, md4_size++)
			{
				if ((temp = CP_to_Unicode[key[++md4_size]]) && md4_size < PLAINTEXT_LENGTH)
					keybuffer[i] = CP_to_Unicode[key[md4_size-1]] | (temp << 16);
				else {
					keybuffer[i] = CP_to_Unicode[key[md4_size-1]] | 0x800000;
					goto key_cleaning_enc;
				}
			}
		keybuffer[i] = 0x80;
	}
key_cleaning_enc:

	i += xBuf;
	for(;i <= *last_length; i += xBuf)
		keybuffer[i] = 0;

	if (xBuf==1) {
#if !ARCH_LITTLE_ENDIAN
		swap(keybuffer, keybuffer, (md4_size>>1)+1);
#endif
		*last_length = (md4_size >> 1) + 1;
	}
	else
		*last_length = md4_size << (xBuf>>2);

	keybuffer[lenStoreOffset] = md4_size << 4;
}

static void set_key_encoding(char *_key, int index)
{
#if defined(NT_X86_64)
	set_key_helper_encoding(&nt_buffer8x[128 * (index >> 3) + index % 8], 8, (unsigned char *)_key, 112, &last_i[index]);
#elif defined(NT_SSE2)
	if(index < NT_NUM_KEYS4)
		set_key_helper_encoding(&nt_buffer4x[64 * (index >> 2) + index % 4], 4, (unsigned char *)_key, 56, &last_i[index]);
	else
		set_key_helper_encoding(&nt_buffer1x[16 * (index - NT_NUM_KEYS4)], 1, (unsigned char *)_key, 14, &last_i[index]);
#else
	set_key_helper_encoding(&nt_buffer1x[index << 4], 1, (unsigned char *)_key, 14,
						&last_i[index]);
//	dump_stuff_msg("setkey ", (unsigned char*)&nt_buffer1x[index << 4], 64);
//	exit(0);
#endif
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
#if defined(NT_X86_64)
	return (char*)utf16_to_enc(get_key_helper(&nt_buffer8x[128 * (index >> 3) +
	                                                index % 8], 8));
#elif defined(NT_SSE2)
	if(index < NT_NUM_KEYS4)
		return (char*)utf16_to_enc(get_key_helper(&nt_buffer4x[64 * (index >> 2) +
		                                                index % 4], 4));
	else
		return (char*)utf16_to_enc(get_key_helper(&nt_buffer1x[16 * (index - NT_NUM_KEYS4)], 1));
#else
	return (char*)utf16_to_enc(get_key_helper(&nt_buffer1x[index << 4], 1));

#endif
}

struct fmt_main fmt_NT = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		fmt_NT_init,
		prepare,
		valid,
		nt_split,
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		NT_CRYPT_FUN,
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
