/*
 * This software is Copyright © 2004 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * UTF-8 support by magnum 2011, no rights reserved
 *
 * microsoft MS SQL cracker
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "sha.h"

//#define MSSQL_DEBUG

#define FORMAT_LABEL			"mssql"
#define FORMAT_NAME			"MS-SQL"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"mssql MMX"
#else
#define ALGORITHM_NAME			"mssql SSE2"
#endif
#else
#define ALGORITHM_NAME			"mssql"
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		25
#define CIPHERTEXT_LENGTH		94

#define BINARY_SIZE			20
#define SALT_SIZE			4

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
//#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) ) //std getpos
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) ) //for endianity conversion
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

static struct fmt_tests mssql_tests[] = {
	{"0x0100A607BA7C54A24D17B565C59F1743776A10250F581D482DA8B6D6261460D3F53B279CC6913CE747006A2E3254", "FOO"},
	{"0x01000508513EADDF6DB7DDD270CCA288BF097F2FF69CC2DB74FBB9644D6901764F999BAB9ECB80DE578D92E3F80D", "BAR"},
	{"0x01008408C523CF06DCB237835D701C165E68F9460580132E28ED8BC558D22CEDF8801F4503468A80F9C52A12C0A3", "CANARD"},
	{"0x0100BF088517935FC9183FE39FDEC77539FD5CB52BA5F5761881E5B9638641A79DBF0F1501647EC941F3355440A2", "LAPIN"},
	{NULL}
};

static unsigned char cursalt[SALT_SIZE];

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mssql_saved_key
#define crypt_key mssql_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) char saved_key[80*4*MMX_COEF];
__declspec(align(16)) char crypt_key[BINARY_SIZE*MMX_COEF];
#else
char saved_key[80*4*MMX_COEF] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
#endif
static unsigned long total_len;
static char plain_keys[MMX_COEF][PLAINTEXT_LENGTH*3+1];
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

static void mssql_set_salt(void *salt)
{
	memcpy(cursalt, salt, SALT_SIZE);
}

static void * mssql_get_salt(char * ciphertext)
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

static void mssql_set_key_enc(char *_key, int index);
extern struct fmt_main fmt_mssql;

static void mssql_init(struct fmt_main *pFmt)
{
	initUnicode(UNICODE_MS_OLD);
#ifdef MMX_COEF
	memset(saved_key, 0, sizeof(saved_key));
#else
	saved_key = mem_alloc_tiny(PLAINTEXT_LENGTH*2 + 1 + SALT_SIZE, MEM_ALIGN_WORD);
#endif
	if (options.utf8) {
		fmt_mssql.methods.set_key = mssql_set_key_enc;
		fmt_mssql.params.plaintext_length = PLAINTEXT_LENGTH * 3;
	}
	else if (options.iso8859_1 || options.ascii) {
		; // do nothing
	}
	else {
		// this function made to handle both utf8 and 'codepage' encodings.
		fmt_mssql.methods.set_key = mssql_set_key_enc;
	}
}

static void mssql_set_key(char *key, int index) {
	UTF8 utf8[PLAINTEXT_LENGTH+1];
	int utf8len, orig_len;
#ifdef MMX_COEF
	int i;
	strnzcpy(plain_keys[index], key, PLAINTEXT_LENGTH);
#else
	plain_keys[index] = key;
#endif
	orig_len = strlen(key);
	utf8len = enc_uc(utf8, PLAINTEXT_LENGTH, (unsigned char*)key, orig_len);
	if (utf8len <= 0 && *key)
		return;

#ifdef MMX_COEF
	if(index==0)
	{
		total_len = 0;
		memset(saved_key, 0, 64*MMX_COEF);
	}

	total_len += (utf8len*2) << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<utf8len;i++)
		saved_key[GETPOS((i*2), index)] = utf8[i];
	saved_key[GETPOS((i*2+SALT_SIZE) , index)] = 0x80;
#else
	key_length = 0;

	while( (((unsigned short *)saved_key)[key_length] = (utf8[key_length] ENDIAN_SHIFT_L ))  )
		key_length++;

#ifdef MSSQL_DEBUG
	printf ("key_len=%d ", key_length);
	dump_stuff(saved_key, key_length<<1);
#endif

#endif
}

static void mssql_set_key_enc(char *key, int index) {
	UTF16 utf16key[PLAINTEXT_LENGTH+1], utf16key_tmp[PLAINTEXT_LENGTH+1];
	int utf8len = strlen(key);
	int i;
	int utf16len;

#ifdef MMX_COEF
	strnzcpy(plain_keys[index], key, PLAINTEXT_LENGTH*3);
#else
	plain_keys[index] = key;
#endif
	utf16len = enc_to_utf16(utf16key_tmp, PLAINTEXT_LENGTH, (unsigned char*)key, utf8len);
	if (utf16len <= 0) {
		utf8len = -utf16len;
		if (utf16len != 0)
			utf16len = strlen16(utf16key_tmp);
	}
	utf16len = utf16_uc(utf16key, PLAINTEXT_LENGTH, utf16key_tmp, utf16len);
	if (utf16len <= 0)
		utf16len *= -1;

#ifdef MMX_COEF
	if(index==0)
	{
		total_len = 0;
		memset(saved_key, 0, 64*MMX_COEF);
	}

	total_len += (utf16len*2) << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<utf16len;i++)
	{
		saved_key[GETPOS((i*2), index)] = (char)utf16key[i];
		saved_key[GETPOS((i*2+1), index)] = (char)(utf16key[i]>>8);
	}
	saved_key[GETPOS((i*2+SALT_SIZE) , index)] = 0x80;
#ifdef MSSQL_DEBUG
	printf ("utf16len=%d ", utf16len);
	dump_stuff_mmx(saved_key, utf16len<<1, index);
#endif

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

#ifdef MSSQL_DEBUG
	printf ("keylen8=%d ", key_length);
	dump_stuff(saved_key, key_length<<1);
#endif

#endif
}

static char *mssql_get_key(int index) {
	static UTF8 UC_Key[PLAINTEXT_LENGTH*3*3+1];
	// Calling this will ONLY upcase characters 'valid' in the code page. There are MANY
	// code pages which mssql WILL upcase the letter (in UCS-2), but there is no upper case value
	// in the code page.  Thus we MUST keep the lower cased letter in this case.
	enc_uc(UC_Key, PLAINTEXT_LENGTH*3*3, (UTF8*)plain_keys[index], strlen(plain_keys[index]));
	return (char*)UC_Key;
}

static int mssql_cmp_all(void *binary, int count) {
#ifdef MMX_COEF
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
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int mssql_cmp_exact(char *source, int count){
  return (1);
}

static int mssql_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return mssql_cmp_all(binary, index);
#endif
}

static void mssql_crypt_all(int count) {
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	unsigned i, index;
	for (index = 0; index < count; ++index)
	{
		unsigned len = (total_len >> ((32/MMX_COEF)*index)) & 0xFF;
		for(i=0;i<SALT_SIZE;i++)
			saved_key[GETPOS((len+i), index)] = cursalt[i];
	}
	shammx( (unsigned char *) crypt_key, (unsigned char *) saved_key, total_len + SALT_EXTRA_LEN);
#else
	SHA_CTX ctx;
	memcpy(saved_key+key_length*2, cursalt, SALT_SIZE);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, saved_key, key_length*2+SALT_SIZE );
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
#endif

}

static void * mssql_binary(char *ciphertext)
{
	static char *realcipher;
	int i;
	if(!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+54])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+55])];
	}
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

static int salt_hash(void *salt)
{
	// This gave much better distribution on a huge set I analysed
	return (*((ARCH_WORD_32 *)salt) >> 8) & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_mssql = {
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
		FMT_8_BIT | FMT_UNICODE | FMT_UTF8,
		mssql_tests
	}, {
		mssql_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		mssql_binary,
		mssql_get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		mssql_set_salt,
		mssql_set_key,
		mssql_get_key,
		fmt_default_clear_keys,
		mssql_crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		mssql_cmp_all,
		mssql_cmp_one,
		mssql_cmp_exact
	}
};
