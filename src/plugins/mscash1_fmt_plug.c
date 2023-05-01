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

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mscash;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mscash);
#else

#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"
#include "options.h"
#include "loader.h"
#include "johnswap.h"
#include "mscash_common.h"

#define FORMAT_LABEL			"mscash"
#define FORMAT_NAME			"MS Cache Hash (DCC)"
#define ALGORITHM_NAME			"MD4 32/" ARCH_BITS_STR

#define PLAINTEXT_LENGTH		27
#define SALT_SIZE			(11*4)

#ifndef OMP_SCALE
#define OMP_SCALE			2 // Tuned w/ MKPC for core i7
#endif

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		512

static unsigned int *ms_buffer1x;
static unsigned int *output1x;
static unsigned int *crypt_out;
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

static void set_key_utf8(char *_key, int index);
static void set_key_encoding(char *_key, int index);
struct fmt_main fmt_mscash;

#if !ARCH_LITTLE_ENDIAN
inline static void swap(unsigned int *x, int count)
{
	while (count--) {
		*x = JOHNSWAP(*x);
		x++;
	}
}
#endif

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	ms_buffer1x = mem_calloc(sizeof(ms_buffer1x[0]), 16*fmt_mscash.params.max_keys_per_crypt);
	output1x    = mem_calloc(sizeof(output1x[0])   ,  4*fmt_mscash.params.max_keys_per_crypt);
	crypt_out   = mem_calloc(sizeof(crypt_out[0])  ,  4*fmt_mscash.params.max_keys_per_crypt);
	last        = mem_calloc(sizeof(last[0])       ,  4*fmt_mscash.params.max_keys_per_crypt);
	last_i      = mem_calloc(sizeof(last_i[0])     ,    fmt_mscash.params.max_keys_per_crypt);

	new_key=1;

	mscash1_adjust_tests(self, options.target_enc, PLAINTEXT_LENGTH,
	                     set_key_utf8, set_key_encoding);
}

static void done(void)
{
	MEM_FREE(last_i);
	MEM_FREE(last);
	MEM_FREE(crypt_out);
	MEM_FREE(output1x);
	MEM_FREE(ms_buffer1x);
}

static void set_salt(void *salt)
{
	salt_buffer=salt;
}

static void *get_salt(char *ciphertext)
{
	unsigned char input[19*3+1];
	int i, utf16len;
	char *lasth = strrchr(ciphertext, '#');
	union {
		UTF16 u16[22];
		uint32_t w[11];
	} static out;

	memset(out.u16, 0, sizeof(out.u16));

	ciphertext += FORMAT_TAG_LEN;

	for (i = 0; &ciphertext[i] < lasth; i++)
		input[i] = ciphertext[i];
	input[i] = 0;

	utf16len = enc_to_utf16(out.u16, 19, input, i);
	if (utf16len < 0)
		utf16len = strlen16(out.u16);

#if ARCH_LITTLE_ENDIAN
	out.u16[utf16len] = 0x80;
#else
	out.u16[utf16len] = 0x8000;
	swap(out.w, (i>>1)+1);
#endif

	out.w[10] = (8 + utf16len) << 4;

//	dump_stuff(out.w, 44);

	return out.u16;
}

static void *get_binary(char *ciphertext)
{
	static unsigned int out[BINARY_SIZE/sizeof(unsigned int)];
	unsigned int i=0;
	unsigned int temp;
	unsigned int *salt=fmt_mscash.methods.salt(ciphertext);

	/* We need to allow salt containing '#' so we search backwards */
	ciphertext = strrchr(ciphertext, '#') + 1;

	for (; i<4 ;i++)
	{
		temp  = ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+0])]))<<4;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+1])]));

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+2])]))<<12;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+3])]))<<8;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+4])]))<<20;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+5])]))<<16;

		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+6])]))<<28;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i*8+7])]))<<24;

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


static int binary_hash_0(void *binary) { return ((unsigned int*)binary)[3] & PH_MASK_0; }
static int binary_hash_1(void *binary) { return ((unsigned int*)binary)[3] & PH_MASK_1; }
static int binary_hash_2(void *binary) { return ((unsigned int*)binary)[3] & PH_MASK_2; }
static int binary_hash_3(void *binary) { return ((unsigned int*)binary)[3] & PH_MASK_3; }
static int binary_hash_4(void *binary) { return ((unsigned int*)binary)[3] & PH_MASK_4; }
static int binary_hash_5(void *binary) { return ((unsigned int*)binary)[3] & PH_MASK_5; }
static int binary_hash_6(void *binary) { return ((unsigned int*)binary)[3] & PH_MASK_6; }

static int get_hash_0(int index) { return output1x[4*index+3] & PH_MASK_0; }
static int get_hash_1(int index) { return output1x[4*index+3] & PH_MASK_1; }
static int get_hash_2(int index) { return output1x[4*index+3] & PH_MASK_2; }
static int get_hash_3(int index) { return output1x[4*index+3] & PH_MASK_3; }
static int get_hash_4(int index) { return output1x[4*index+3] & PH_MASK_4; }
static int get_hash_5(int index) { return output1x[4*index+3] & PH_MASK_5; }
static int get_hash_6(int index) { return output1x[4*index+3] & PH_MASK_6; }

static void nt_hash(int count)
{
	int i;

#if defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, ms_buffer1x, crypt_out, last)
#endif
	for (i = 0; i < count; i++) {
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

		crypt_out[4*i+0] = a + INIT_A;
		crypt_out[4*i+1] = b + INIT_B;
		crypt_out[4*i+2] = c + INIT_C;
		crypt_out[4*i+3] = d + INIT_D;

		//Another MD4_crypt for the salt
		/* Round 1 */
		a= 	        0xFFFFFFFF 	            +crypt_out[4*i+0]; a=(a<<3 )|(a>>29);
		d=INIT_D + ( INIT_C ^ ( a & 0x77777777))    +crypt_out[4*i+1]; d=(d<<7 )|(d>>25);
		c=INIT_C + ( INIT_B ^ ( d & ( a ^ INIT_B))) +crypt_out[4*i+2]; c=(c<<11)|(c>>21);
		b=INIT_B + (    a   ^ ( c & ( d ^    a  ))) +crypt_out[4*i+3]; b=(b<<19)|(b>>13);

		last[4*i+0]=a;
		last[4*i+1]=b;
		last[4*i+2]=c;
		last[4*i+3]=d;
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i;

	if (new_key)
	{
		new_key=0;
		nt_hash(count);
	}

#if defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, last, crypt_out, salt_buffer, output1x)
#endif
	for (i = 0; i < count; i++) {
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
		a += ((b & (c | d)) | (c & d))  +  crypt_out[4*i+0]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[0]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[4]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[8]  + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt_out[4*i+1]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[1]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[5]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[9]  + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt_out[4*i+2]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[2]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[6]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))  +  salt_buffer[10] + SQRT_2; b = (b << 13) | (b >> 19);

		a += ((b & (c | d)) | (c & d))  +  crypt_out[4*i+3]    + SQRT_2; a = (a << 3 ) | (a >> 29);
		d += ((a & (b | c)) | (b & c))  +  salt_buffer[3]  + SQRT_2; d = (d << 5 ) | (d >> 27);
		c += ((d & (a | b)) | (a & b))  +  salt_buffer[7]  + SQRT_2; c = (c << 9 ) | (c >> 23);
		b += ((c & (d | a)) | (d & a))/*+ salt_buffer[11]*/+ SQRT_2; b = (b << 13) | (b >> 19);

		/* Round 3 */
		a += (b ^ c ^ d) + crypt_out[4*i+0]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[4]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[0]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[8]  +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + crypt_out[4*i+2]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[6]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
		c += (d ^ a ^ b) + salt_buffer[2]  +  SQRT_3; c = (c << 11) | (c >> 21);
		b += (c ^ d ^ a) + salt_buffer[10] +  SQRT_3; b = (b << 15) | (b >> 17);

		a += (b ^ c ^ d) + crypt_out[4*i+1]    +  SQRT_3; a = (a << 3 ) | (a >> 29);
		d += (a ^ b ^ c) + salt_buffer[5];

		output1x[4*i+0]=a;
		output1x[4*i+1]=b;
		output1x[4*i+2]=c;
		output1x[4*i+3]=d;
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i=0;
	unsigned int d=((unsigned int *)binary)[3];

	for (;i<count;i++)
		if (d==output1x[i*4+3])
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

	if (d!=t[3])
		return 0;
	d+=SQRT_3;d = (d << 9 ) | (d >> 23);

	c += (d ^ a ^ b) + salt_buffer[1]  +  SQRT_3; c = (c << 11) | (c >> 21);
	if (c!=t[2])
		return 0;

	b += (c ^ d ^ a) + salt_buffer[9]  +  SQRT_3; b = (b << 15) | (b >> 17);
	if (b!=t[1])
		return 0;

	a += (b ^ c ^ d) + crypt_out[4*index+3]+  SQRT_3; a = (a << 3 ) | (a >> 29);
	return (a==t[0]);
}

static int cmp_exact(char *source, int index)
{
	// This check is for the unreal case of collisions.
	// It verifies that the salts are the same.
	unsigned int *salt=fmt_mscash.methods.salt(source);
	unsigned int i=0;
	for (;i<11;i++)
		if (salt[i]!=salt_buffer[i])
			return 0;
	return 1;
}

// This is common code for the SSE/MMX/generic variants of non-UTF8 set_key
inline static void set_key_helper(unsigned int * keybuffer,
                                  unsigned int xBuf,
                                  const unsigned char * key,
                                  unsigned int lenStoreOffset,
                                  unsigned int *last_length)
{
	unsigned int i=0;
	unsigned int md4_size=0;
	for (; key[md4_size] && md4_size < PLAINTEXT_LENGTH; i += xBuf, md4_size++)
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
	for (;i <= *last_length; i += xBuf)
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
}

// UTF-8 conversion right into key buffer
// This is common code for the SSE/MMX/generic variants
inline static void set_key_helper_utf8(unsigned int * keybuffer, unsigned int xBuf,
    const UTF8 * source, unsigned int lenStoreOffset, unsigned int *lastlen)
{
	unsigned int *target = keybuffer;
	UTF32 chl, chh = 0x80;
	unsigned int outlen = 0;

	while (*source) {
		chl = *source;
		if (chl >= 0xC0) {
			unsigned int extraBytesToRead = opt_trailingBytesUTF8[chl & 0x3f];
			switch (extraBytesToRead) {
			case 3:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else {
					*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
					return;
				}
			case 2:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else {
					*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
					return;
				}
			case 1:
				++source;
				if (*source) {
					chl <<= 6;
					chl += *source;
				} else {
					*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
					return;
				}
			case 0:
				break;
			default:
				*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
				return;
			}
			chl -= offsetsFromUTF8[extraBytesToRead];
		}
		source++;
		outlen++;
		if (chl > UNI_MAX_BMP) {
			if (outlen == PLAINTEXT_LENGTH) {
				chh = 0x80;
				*target = (chh << 16) | chl;
				target += xBuf;
				*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
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
			outlen++;
		} else if (*source && outlen < PLAINTEXT_LENGTH) {
			chh = *source;
			if (chh >= 0xC0) {
				unsigned int extraBytesToRead =
					opt_trailingBytesUTF8[chh & 0x3f];
				switch (extraBytesToRead) {
				case 3:
					++source;
					if (*source) {
						chl <<= 6;
						chl += *source;
					} else {
						*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
						return;
					}
				case 2:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else {
						*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
						return;
					}
				case 1:
					++source;
					if (*source) {
						chh <<= 6;
						chh += *source;
					} else {
						*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
						return;
					}
				case 0:
					break;
				default:
					*lastlen = ((PLAINTEXT_LENGTH >> 1) + 1) * xBuf;
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
	set_key_helper_utf8(&ms_buffer1x[index << 4], 1, (UTF8 *)_key, 14,
	                &last_i[index]);
	//new password_candidate
	new_key=1;
}

// This is common code for the SSE/MMX/generic variants of non-UTF8 non-ISO-8859-1 set_key
inline static void set_key_helper_encoding(unsigned int * keybuffer,
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
	for (;i <= *last_length; i += xBuf)
		keybuffer[i] = 0;

#if !ARCH_LITTLE_ENDIAN
	swap(keybuffer, (md4_size>>1)+1);
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
}


// Get the key back from the key buffer, from UCS-2 LE
static char *get_key(int index)
{
	static union {
		UTF16 u16[PLAINTEXT_LENGTH + 1];
		unsigned int u32[(PLAINTEXT_LENGTH + 1 + 1) / 2];
	} key;
	unsigned int * keybuffer = &ms_buffer1x[index << 4];
	unsigned int md4_size;
	unsigned int i=0;
	int len = keybuffer[14] >> 4;

	for (md4_size = 0; md4_size < len; i++, md4_size += 2)
	{
#if ARCH_LITTLE_ENDIAN
		key.u16[md4_size] = keybuffer[i];
		key.u16[md4_size+1] = keybuffer[i] >> 16;
#else
		key.u16[md4_size] = keybuffer[i] >> 16;
		key.u16[md4_size+1] = keybuffer[i];
#endif
	}
#if !ARCH_LITTLE_ENDIAN
	swap(key.u32, md4_size >> 1);
#endif
	key.u16[len] = 0x00;

	return (char *)utf16_to_enc(key.u16);
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
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAG },
		mscash1_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		mscash1_common_prepare,
		mscash1_common_valid,
		mscash1_common_split,
		get_binary,	// NOTE, not using the 'common' binary function.
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		NULL,
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
