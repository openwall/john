/*
 * This software is Copyright © 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

#define FORMAT_LABEL			"hmac-md5"
#define FORMAT_NAME			"HMAC MD5"

#ifdef MD5_SSE_PARA
#define MMX_COEF 4
#include "sse-intrinsics.h"
#define MD5_N				(MD5_SSE_PARA*MMX_COEF)
#else
#define MD5_N				MMX_COEF
#endif

#ifdef MD5_N_STR
#define ALGORITHM_NAME			"SSE2i " MD5_N_STR
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
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		128

#define BINARY_SIZE			16
#define SALT_SIZE			64

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N
#define GETPOS(i, index)        ( ((index)&3)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) + ((index)>>2)*64*MMX_COEF )

#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests hmacmd5_tests[] = {
	{"what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738", "Jefe"},
	{"YT1m11GDMm3oze0EdqO3FZmATSrxhquB#6c97850b296b34719b7cea5c0c751e22", ""},
	{"2shXeqDlLdZ2pSMc0CBHfTyA5a9TKuSW#dfeb02c6f8a9ce89b554be60db3a2333", "magnum"},
	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define crypt_key hmacmd5_crypt_key
#define opad hmacmd5_opad
#define ipad hmacmd5_ipad
#define cursalt hmacmd5_cursalt
#define dump hmacmd5_dump
#ifdef _MSC_VER
__declspec(align(16)) char crypt_key[64*4*MD5_N];
__declspec(align(16)) unsigned char opad[PLAINTEXT_LENGTH*MD5_N];
__declspec(align(16)) unsigned char ipad[PLAINTEXT_LENGTH*MD5_N];
__declspec(align(16)) unsigned char cursalt[SALT_SIZE*MD5_N];
__declspec(align(16)) unsigned char dump[BINARY_SIZE*MD5_N];
#else
char crypt_key[64*4*MD5_N] __attribute__ ((aligned(16)));
unsigned char opad[PLAINTEXT_LENGTH*MD5_N] __attribute__ ((aligned(16)));
unsigned char ipad[PLAINTEXT_LENGTH*MD5_N] __attribute__ ((aligned(16)));
unsigned char cursalt[SALT_SIZE*MD5_N] __attribute__ ((aligned(16)));
unsigned char dump[BINARY_SIZE*MD5_N] __attribute__((aligned(16)));
#endif
static ARCH_WORD_32 total_len;
#else
static char crypt_key[BINARY_SIZE+1];
static MD5_CTX ctx;
static unsigned char opad[PLAINTEXT_LENGTH];
static unsigned char ipad[PLAINTEXT_LENGTH];
static unsigned char cursalt[SALT_SIZE];
#endif
static unsigned char out[PLAINTEXT_LENGTH + 1];

static void hmacmd5_init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	int i;
	for (i = 0; i < MD5_N; ++i) {
		crypt_key[GETPOS(BINARY_SIZE,i)] = 0x80;
		((unsigned int *)crypt_key)[14*MMX_COEF + (i&3) + (i>>2)*64] = (BINARY_SIZE+64)<<3;
	}
#endif
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int pos, i;

	for(i=0;(i<strlen(ciphertext)) && (ciphertext[i]!='#');i++) ;
	if(i==strlen(ciphertext))
		return 0;
	pos = i+1;
	if (strlen(ciphertext+pos) != BINARY_SIZE*2) return 0;
	for (i = pos; i < BINARY_SIZE*2+pos; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void hmacmd5_set_salt(void *salt)
{
#ifdef MMX_COEF
	memcpy(cursalt, salt, SALT_SIZE * MD5_N);
#else
	memcpy(cursalt, salt, SALT_SIZE);
#endif
}

static void hmacmd5_set_key(char *key, int index) {
	int i;
	int len;

	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

#ifdef MMX_COEF
	if(index==0)
	{
		memset(ipad, 0x36, sizeof(ipad));
		memset(opad, 0x5C, sizeof(opad));
	}

	for(i=0;i<len;i++)
	{
		ipad[GETPOS(i, index)] ^= key[i];
		opad[GETPOS(i, index)] ^= key[i];
	}
#else
	memset(ipad, 0x36, PLAINTEXT_LENGTH);
	memset(opad, 0x5C, PLAINTEXT_LENGTH);
	for(i=0;i<len;i++)
	{
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
#endif
}

static char *hmacmd5_get_key(int index) {
	unsigned int i;
	for(i=0;i<PLAINTEXT_LENGTH;i++)
#ifdef MMX_COEF
		out[i] = ipad[ GETPOS(i, index) ] ^ 0x36;
#else
		out[i] = ipad[ i ] ^ 0x36;
#endif
	out[i] = 0;
	return (char *) out;
}

static int hmacmd5_cmp_all(void *binary, int index) {
	int i=0;
#ifdef MMX_COEF
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF > 3)
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+2])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+3])
#ifdef MD5_SSE_PARA
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+0+16*1*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+1+16*1*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+2+16*1*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+3+16*1*MMX_COEF])
#endif
#if (MD5_SSE_PARA>2)
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+0+16*2*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+1+16*2*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+2+16*2*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+3+16*2*MMX_COEF])
#endif
#if (MD5_SSE_PARA>3)
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+0+16*3*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+1+16*3*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+2+16*3*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+3+16*3*MMX_COEF])
#endif
#if (MD5_SSE_PARA>4)
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+0+16*4*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+1+16*4*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+2+16*4*MMX_COEF])
			&& ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+3+16*4*MMX_COEF])
#endif
#if (MD5_SSE_PARA>5)
#error hmac_md5 format only handles MD5_SSE_PARA up to 5, not over.
#endif
#endif
		)
			return 0;
		i++;
	}
#else
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)crypt_key)[i])
			return 0;
		i++;
	}
#endif
	return 1;
}

static int hmacmd5_cmp_exact(char *source, int count){
  return (1);
}

static int hmacmd5_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+(index&3)+(index>>2)*16*MMX_COEF] )
			return 0;
	return 1;
#else
	return hmacmd5_cmp_all(binary, index);
#endif
}

static void hmacmd5_crypt_all(int count) {

#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	int i;
	SSEmd5body(ipad, ((unsigned int *)dump), 1);
	SSEmd5body(cursalt, ((unsigned int *)dump), 0);
	for (i = 0; i < MD5_SSE_PARA; ++i)
		memcpy(&crypt_key[64*4*i], &dump[64*i], 64);
	SSEmd5body(opad, ((unsigned int *)dump), 1);
	SSEmd5body(crypt_key, ((unsigned int *)dump), 0);
	for (i = 0; i < MD5_SSE_PARA; ++i)
		memcpy(&crypt_key[64*4*i], &dump[64*i], 64);
#else
	mdfivemmx_nosizeupdate( dump, ipad, 64);
	// note, total_len is NOT computed since we moved salt setting to salt, and not get_salt.
	total_len = ((ARCH_WORD_32*)cursalt)[14*MMX_COEF] >> 3;
//	mdfivemmx_noinit_uniformsizeupdate( (unsigned char *) crypt_key, cursalt, total_len + 64);
	mdfivemmx_noinit_uniformsizeupdate( (unsigned char *) crypt_key, cursalt, total_len);
	mdfivemmx_nosizeupdate( dump, opad, 64);
	mdfivemmx_noinit_uniformsizeupdate( (unsigned char *) crypt_key, (unsigned char *) crypt_key, BINARY_SIZE + 64);
#endif
#else
	MD5_Init( &ctx );
	MD5_Update( &ctx, ipad, 64 );
	MD5_Update( &ctx, cursalt, strlen( (char *) cursalt) );
	MD5_Final( (unsigned char *) crypt_key, &ctx);
	MD5_Init( &ctx );
	MD5_Update( &ctx, opad, 64 );
	MD5_Update( &ctx, crypt_key, BINARY_SIZE);
	MD5_Final( (unsigned char *) crypt_key, &ctx);
#endif

}

static void * hmacmd5_binary(char *ciphertext)
{
	static unsigned char realcipher[BINARY_SIZE];
	int i,pos;

	for(i=0;ciphertext[i]!='#';i++);
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];
	}
	return (void *)realcipher;
}

static void * hmacmd5_salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];
	int i=0;
#ifdef MMX_COEF
	int j;
#endif
	memset(salt, 0, sizeof(salt));
	while(ciphertext[i]!='#')
	{
		salt[i] = ciphertext[i];
		i++;
	}
#ifdef MMX_COEF
	total_len = 0;
	while(((unsigned char *)salt)[total_len])
	{
		for (i = 0; i < MD5_N; ++i)
			cursalt[GETPOS(total_len,i)] = ((unsigned char *)salt)[total_len];
		++total_len;
	}
	for (i = 0; i < MD5_N; ++i)
		cursalt[GETPOS(total_len, i)] = 0x80;
	for (j = total_len + 1; j < SALT_SIZE; ++j) {
		for (i = 0; i < MD5_N; ++i)
			cursalt[GETPOS(j,i)] = 0;
	}
	for (i = 0; i < MD5_N; ++i) {
		((unsigned int *)cursalt)[14*MMX_COEF + (i&3) + (i>>2)*16*MMX_COEF] = (total_len+64)<<3;
	}
	return cursalt;
#else
	return salt;
#endif
}

struct fmt_main fmt_hmacMD5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#ifdef MMX_COEF
		SALT_SIZE * MD5_N,
#else
		SALT_SIZE,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		hmacmd5_tests
	}, {
		hmacmd5_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		hmacmd5_binary,
		hmacmd5_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		hmacmd5_set_salt,
		hmacmd5_set_key,
		hmacmd5_get_key,
		fmt_default_clear_keys,
		hmacmd5_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		hmacmd5_cmp_all,
		hmacmd5_cmp_one,
		hmacmd5_cmp_exact
	}
};
