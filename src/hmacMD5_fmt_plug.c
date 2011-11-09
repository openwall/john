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
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"hmac-md5 MMX"
#else
#define ALGORITHM_NAME			"hmac-md5 SSE2"
#endif
#else
#define ALGORITHM_NAME			"hmac-md5"
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		128

#define BINARY_SIZE			16
#define SALT_SIZE			64

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests hmacmd5_tests[] = {
	{"what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738", "Jefe"},
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
__declspec(align(16)) char crypt_key[64*MMX_COEF];
__declspec(align(16)) unsigned char opad[PLAINTEXT_LENGTH*MMX_COEF];
__declspec(align(16)) unsigned char ipad[PLAINTEXT_LENGTH*MMX_COEF];
__declspec(align(16)) unsigned char cursalt[SALT_SIZE*MMX_COEF];
__declspec(align(16)) unsigned char dump[BINARY_SIZE*MMX_COEF];
#else
char crypt_key[64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char opad[PLAINTEXT_LENGTH*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char ipad[PLAINTEXT_LENGTH*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char cursalt[SALT_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char dump[BINARY_SIZE*MMX_COEF] __attribute__((aligned(16)));
#endif
static unsigned long total_len;
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
	memset(crypt_key, 0, sizeof(crypt_key));
	crypt_key[GETPOS(BINARY_SIZE,0)] = 0x80;
	crypt_key[GETPOS(BINARY_SIZE,1)] = 0x80;
#if (MMX_COEF == 4)
	crypt_key[GETPOS(BINARY_SIZE,2)] = 0x80;
	crypt_key[GETPOS(BINARY_SIZE,3)] = 0x80;
#endif
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
	total_len = 0;
	while(((unsigned char *)salt)[total_len])
	{
		cursalt[GETPOS(total_len, 0)] = ((unsigned char *)salt)[total_len];
		cursalt[GETPOS(total_len, 1)] = ((unsigned char *)salt)[total_len];
#if (MMX_COEF == 4)
		cursalt[GETPOS(total_len, 2)] = ((unsigned char *)salt)[total_len];
		cursalt[GETPOS(total_len, 3)] = ((unsigned char *)salt)[total_len];
#endif
		total_len ++;
	}
	cursalt[GETPOS(total_len, 0)] = 0x80;
	cursalt[GETPOS(total_len, 1)] = 0x80;
#if (MMX_COEF == 4)
	cursalt[GETPOS(total_len, 2)] = 0x80;
	cursalt[GETPOS(total_len, 3)] = 0x80;
#endif
	{
		int i;
		for (i = total_len + 1; i < SALT_SIZE; i++) {
			cursalt[GETPOS(i, 0)] = 0;
			cursalt[GETPOS(i, 1)] = 0;
#if (MMX_COEF == 4)
			cursalt[GETPOS(i, 2)] = 0;
			cursalt[GETPOS(i, 3)] = 0;
#endif
		}
	}
	//total_len += 64;
	//total_len += (total_len<<16);
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
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return hmacmd5_cmp_all(binary, index);
#endif
}

static void hmacmd5_crypt_all(int count) {

#ifdef MMX_COEF
	int i;
	i = mdfivemmx_nosizeupdate( dump, ipad, 64);
	i = mdfivemmx_noinit_uniformsizeupdate( (unsigned char *) crypt_key, cursalt, total_len + 64);
	i = mdfivemmx_nosizeupdate( dump, opad, 64);
	i = mdfivemmx_noinit_uniformsizeupdate( (unsigned char *) crypt_key, (unsigned char *) crypt_key, BINARY_SIZE + 64);
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
	memset(salt, 0, SALT_SIZE);
	while(ciphertext[i]!='#')
	{
		salt[i] = ciphertext[i];
		i++;
	}
	salt[i]=0;
	return salt;
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
		SALT_SIZE,
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
