/*
 * This software is Copyright © 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Modified by Mathieu Perrin (mathieu at tpfh.org) 09/06
 * Microsoft MS-SQL05 password cracker
 *
 * UTF-8 support and use of intrinsics by magnum 2011, no rights reserved
 *
 */

#include <string.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF	4
#include "sse-intrinsics.h"
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS	MMX_COEF
#endif

#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "sha.h"

#define FORMAT_LABEL			"mssql05"
#define FORMAT_NAME			"MS-SQL05"

#ifdef SHA1_N_STR
#define ALGORITHM_NAME			"SSE2i " SHA1_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define ALGORITHM_NAME			"SSE2 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define ALGORITHM_NAME			"MMX 2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		25
#define CIPHERTEXT_LENGTH		54

#define BINARY_SIZE			20
#define SALT_SIZE			4

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*80*MMX_COEF*4 ) //for endianity conversion
#if (MMX_COEF==2)
#define SALT_EXTRA_LEN          0x40004
#else
#define SALT_EXTRA_LEN          0x4040404
#endif
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

//microsoft unicode ...
#if ARCH_LITTLE_ENDIAN
#define ENDIAN_SHIFT_L
#define ENDIAN_SHIFT_R
#else
#define ENDIAN_SHIFT_L  << 8
#define ENDIAN_SHIFT_R  >> 8
#endif

static struct fmt_tests tests[] = {
	{"0x01004086CEB6BF932BC4151A1AF1F13CD17301D70816A8886908", "toto"},
	{"0x01004086CEB60ED526885801C23B366965586A43D3DEAC6DD3FD", "titi"},
	{"0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254", "foo",    {"User1"} },
	{"0x01000508513EADDF6DB7DDD270CCA288BF097F2FF69CC2DB74FBB9644D6901764F999BAB9ECB80DE578D92E3F80D", "bar",    {"User2"} },
	{"0x01008408C523CF06DCB237835D701C165E68F9460580132E28ED8BC558D22CEDF8801F4503468A80F9C52A12C0A3", "canard", {"User3"} },
	{"0x0100BF088517935FC9183FE39FDEC77539FD5CB52BA5F5761881E5B9638641A79DBF0F1501647EC941F3355440A2", "lapin",  {"User4"} },
	{NULL}
};

static unsigned char cursalt[SALT_SIZE];

#ifdef MMX_COEF
#ifdef _MSC_VER
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mssql05_saved_key
#define crypt_key mssql05_crypt_key
__declspec(align(16)) char saved_key[80*4*NBKEYS];
__declspec(align(16)) char crypt_key[BINARY_SIZE*NBKEYS];
#else
static char saved_key[80*4*NBKEYS] __attribute__ ((aligned(16)));
static char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
#endif
#ifndef SHA1_SSE_PARA
static unsigned long total_len;
#endif
static char plain_keys[NBKEYS][PLAINTEXT_LENGTH*3+1];
#else

static unsigned char *saved_key;
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static unsigned int key_length;
static char *plain_keys[1];

#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	if(memcmp(ciphertext, "0x0100", 6))
		return 0;
	for (i = 6; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

// Handle full hashes (old and new in one long string) as well. This means the
// [other] mssql format should be registered before this one. If there are
// old-style hashes we should crack them first using that format, then run
// mssql05 with -ru:nt just like LM -> NT format
static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	if (strlen(split_fields[1]) == CIPHERTEXT_LENGTH)
		return split_fields[1];

	if (!memcmp(split_fields[1], "0x0100", 6) && strlen(split_fields[1]) == 94) {
		char cp[CIPHERTEXT_LENGTH + 1];
		strnzcpy(cp, split_fields[1], CIPHERTEXT_LENGTH + 1);

		if (valid(cp,pFmt)) {
			char *cp2 = str_alloc_copy(cp);
			return cp2;
		}
	}
	return split_fields[1];
}

static void set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void * get_salt(char * ciphertext)
{
	static unsigned char *out2;
	int l;

	if (!out2) out2 = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

	for(l=0;l<SALT_SIZE;l++)
	{
		out2[l] = atoi16[ARCH_INDEX(ciphertext[l*2+6])]*16
			+ atoi16[ARCH_INDEX(ciphertext[l*2+7])];
	}

	return out2;
}

static void set_key_enc(char *_key, int index);
extern struct fmt_main fmt_mssql05;

static void init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	memset(saved_key, 0, sizeof(saved_key));
#else
	saved_key = mem_alloc_tiny(PLAINTEXT_LENGTH*2 + 1 + SALT_SIZE, MEM_ALIGN_WORD);
#endif
	if (options.utf8) {
		fmt_mssql05.methods.set_key = set_key_enc;
		fmt_mssql05.params.plaintext_length = PLAINTEXT_LENGTH * 3;
	}
	else if (options.iso8859_1 || options.ascii) {
		; // do nothing
	}
	else {
		// this function made to handle both utf8 and 'codepage' encodings.
		fmt_mssql05.methods.set_key = set_key_enc;
	}
}

static void set_key(char *_key, int index) {
	unsigned char *key = (unsigned char*)_key;
#ifdef MMX_COEF
	int len;
	int i;
	strnzcpy(plain_keys[index], _key, PLAINTEXT_LENGTH + 1);
	len = strlen(_key);
#else
	plain_keys[index] = _key;
#endif

#ifdef MMX_COEF
	if(index==0)
	{
#ifdef SHA1_SSE_PARA
		int j;
		for (j=0; j<SHA1_SSE_PARA; j++)
			memset(saved_key+j*4*80*MMX_COEF, 0, 60*MMX_COEF);
#else
		memset(saved_key, 0, 60*MMX_COEF);
		total_len = 0;
#endif
	}
#ifdef SHA1_SSE_PARA
	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] = (2*len+SALT_SIZE)<<3;
#else
	total_len += (len*2) << ( ( (32/MMX_COEF) * index ) );
#endif
	for(i=0;i<len;i++)
		saved_key[GETPOS((i*2), index)] = key[i];
	saved_key[GETPOS((i*2+SALT_SIZE) , index)] = 0x80;
#else
	key_length = 0;

	while( (((unsigned short *)saved_key)[key_length] = (key[key_length] ENDIAN_SHIFT_L ))  )
		key_length++;
#endif
}

static void set_key_enc(char *key, int index) {
	UTF16 utf16key[PLAINTEXT_LENGTH+1];
	int utf8len = strlen(key);
	int i;
	int utf16len;

#ifdef MMX_COEF
	strnzcpy(plain_keys[index], key, PLAINTEXT_LENGTH*3 + 1);
#else
	plain_keys[index] = key;
#endif
	utf16len = enc_to_utf16(utf16key, PLAINTEXT_LENGTH, (unsigned char*)key, utf8len);
	if (utf16len <= 0) {
		utf8len = -utf16len;
		plain_keys[index][utf8len] = 0; // match truncation!
		if (utf16len != 0)
			utf16len = strlen16(utf16key);
	}

#ifdef MMX_COEF
	if(index==0)
	{
#ifdef SHA1_SSE_PARA
		int j;
		for (j=0; j<SHA1_SSE_PARA; j++)
			memset(saved_key+j*4*80*MMX_COEF, 0, 60*MMX_COEF);
#else
		memset(saved_key, 0, 60*MMX_COEF);
		total_len = 0;
#endif
	}

#ifdef SHA1_SSE_PARA
	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] = (2*utf16len+SALT_SIZE)<<3;
#else
	total_len += (utf16len*2) << ( ( (32/MMX_COEF) * index ) );
#endif
	for(i=0;i<utf16len;i++)
	{
		saved_key[GETPOS((i*2), index)] = (char)utf16key[i];
		saved_key[GETPOS((i*2+1), index)] = (char)(utf16key[i]>>8);
	}
	saved_key[GETPOS((i*2+SALT_SIZE) , index)] = 0x80;
#else
	for(i=0;i<utf16len;i++)
	{
		unsigned char *uc = (unsigned char*)&(utf16key[i]);
#if ARCH_LITTLE_ENDIAN
		saved_key[(i<<1)  ] = uc[0];
		saved_key[(i<<1)+1] = uc[1];
#else
		saved_key[(i<<1)  ] = uc[1];
		saved_key[(i<<1)+1] = uc[0];
#endif
	}
	key_length = i;
#endif
}

static char *get_key(int index) {
	return (char*) plain_keys[index];
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
#ifdef SHA1_SSE_PARA
	unsigned int x,y=0;

	for(;y<SHA1_SSE_PARA;y++)
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((unsigned int *)binary)[0] == ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	int i=0;
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF > 3)
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+2])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+3])
#endif
		)
			return 0;
		i++;
	}
	return 1;
#endif
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count){
  return (1);
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
#if SHA1_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((unsigned int *)binary)[0] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] )
		return 0;
	if( ((unsigned int *)binary)[1] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+4] )
		return 0;
	if( ((unsigned int *)binary)[2] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+8] )
		return 0;
	if( ((unsigned int *)binary)[3] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+12] )
		return 0;
	if( ((unsigned int *)binary)[4] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+16] )
		return 0;
	return 1;
#else
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#endif
#else
	return cmp_all(binary, index);
#endif
}

static void crypt_all(int count) {
#ifdef MMX_COEF
	unsigned i, index;
	for (index = 0; index < count; ++index)
	{
#ifdef SHA1_SSE_PARA
		unsigned len = (((((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF]) >> 3) & 0xff) - SALT_SIZE;
#else
		unsigned len = (total_len >> ((32/MMX_COEF)*index)) & 0xFF;
#endif
		for(i=0;i<SALT_SIZE;i++)
			saved_key[GETPOS((len+i), index)] = cursalt[i];
	}
#ifdef SHA1_SSE_PARA
	SSESHA1body(saved_key, (unsigned int *)crypt_key, NULL, 0);
#else
	shammx( (unsigned char *) crypt_key, (unsigned char *) saved_key, total_len + SALT_EXTRA_LEN);
#endif
#else
	SHA_CTX ctx;
	memcpy(saved_key+key_length*2, cursalt, SALT_SIZE);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, saved_key, key_length*2+SALT_SIZE );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif

}

static void * binary(char *ciphertext)
{
	static char *realcipher;
	int i;

	if(!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+14])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+15])];
	}
#ifdef SHA1_SSE_PARA
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static int binary_hash_0(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFFF;
}

#ifdef SHA1_SSE_PARA
static int get_hash_0(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] & 0xfffff;
}
#else
static int get_hash_0(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xF;
}

static int get_hash_1(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFF;
}

static int get_hash_2(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFF;
}

static int get_hash_3(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFFF;
}
#endif

static int salt_hash(void *salt)
{
	// This gave much better distribution on a huge set I analysed
	return (*((ARCH_WORD_32 *)salt) >> 8) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_mssql05 = {
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
		FMT_CASE | FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		prepare,
		valid,
		fmt_default_split,
		binary,
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
