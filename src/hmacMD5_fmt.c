/*
 * This software is Copyright © 2010 bartavelle, <bartavelle at bandecon.com>, and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Various optimisations by magnum 2011-2012, licensed under the same terms as
 * above.
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

#ifdef MD5_SSE_PARA
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

#define PLAINTEXT_LENGTH		125

#define PAD_SIZE			64
#define BINARY_SIZE			16
#define SALT_SIZE			PAD_SIZE

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF +    ((i)&3)  + (index>>(MMX_COEF>>1))*64*MMX_COEF )

#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"what do ya want for nothing?#750c783e6ab0b503eaa86e310a5db738", "Jefe"},
	{"YT1m11GDMm3oze0EdqO3FZmATSrxhquB#6c97850b296b34719b7cea5c0c751e22", ""},
	{"2shXeqDlLdZ2pSMc0CBHfTyA5a9TKuSW#dfeb02c6f8a9ce89b554be60db3a2333", "magnum"},
	{"#74e6f7298a9c2d168935f58c001bad88", ""},
	{"The quick brown fox jumps over the lazy dog#80070713463e7749b90c2dc24911e275", "key"},
	{"Beppe Grillo#f8457c3046c587bbcbd6d7036ba42c81", "Io credo nella reincarnazione e sono di Genova; per cui ho fatto testamento e mi sono lasciato tutto a me."},
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
__declspec(align(16)) unsigned char crypt_key[64*MD5_N];
__declspec(align(16)) unsigned char opad[64*MD5_N];
__declspec(align(16)) unsigned char ipad[64*MD5_N];
__declspec(align(16)) unsigned char cursalt[SALT_SIZE*MD5_N];
__declspec(align(16)) unsigned char dump[BINARY_SIZE*MD5_N];
#else
unsigned char crypt_key[64*MD5_N] __attribute__ ((aligned(16)));
unsigned char opad[64*MD5_N] __attribute__ ((aligned(16)));
unsigned char ipad[64*MD5_N] __attribute__ ((aligned(16)));
unsigned char cursalt[SALT_SIZE*MD5_N] __attribute__ ((aligned(16)));
unsigned char dump[BINARY_SIZE*MD5_N] __attribute__((aligned(16)));
#endif
static char saved_plain[MD5_N][PLAINTEXT_LENGTH + 1];
#else
static char crypt_key[BINARY_SIZE+1];
static unsigned char opad[PAD_SIZE];
static unsigned char ipad[PAD_SIZE];
static unsigned char cursalt[SALT_SIZE];
static char saved_plain[PLAINTEXT_LENGTH + 1];
#endif

static void init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	int i;
	for (i = 0; i < MD5_N; ++i) {
		crypt_key[GETPOS(BINARY_SIZE, i)] = 0x80;
		((unsigned int*)crypt_key)[14*MMX_COEF + (i&3) + (i>>2)*16*MMX_COEF] = (BINARY_SIZE+64)<<3;
	}
#endif
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int pos, i;
	char *p;

	p = strrchr(ciphertext, '#'); // allow # in salt
	if (!p || p > &ciphertext[strlen(ciphertext)-1]) return 0;
	i = (int)(p - ciphertext);
#if MMX_COEF
	if(i > 55) return 0;
#else
	if(i > SALT_SIZE) return 0;
#endif
	pos = i+1;
	if (strlen(ciphertext+pos) != BINARY_SIZE*2) return 0;
	for (i = pos; i < BINARY_SIZE*2+pos; i++)
	{
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
		        (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
		        || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void set_salt(void *salt)
{
#ifdef MMX_COEF
	memcpy(cursalt, salt, SALT_SIZE * MD5_N);
#else
	memcpy(cursalt, salt, SALT_SIZE);
#endif
}

static void set_key(char *key, int index)
{
	int len;
#ifdef MMX_COEF
	ARCH_WORD_32 *ipadp = (ARCH_WORD_32*)&ipad[GETPOS(0, index)];
	ARCH_WORD_32 *opadp = (ARCH_WORD_32*)&opad[GETPOS(0, index)];
	const ARCH_WORD_32 *keyp = (ARCH_WORD_32*)key;
	unsigned int temp;

	if(index==0)
	{
		memset(ipad, 0x36, sizeof(ipad));
		memset(opad, 0x5C, sizeof(opad));
	}

	len = strlen(key);
	memcpy(saved_plain[index], key, len);
	saved_plain[index][len] = 0;

	if (len > PAD_SIZE) {
		unsigned char k0[BINARY_SIZE];
		MD5_CTX ctx;
		int i;

		MD5_Init( &ctx );
		MD5_Update( &ctx, key, len);
		MD5_Final( k0, &ctx);

		keyp = (unsigned int*)k0;
		for(i = 0; i < BINARY_SIZE / 4; i++, ipadp += MMX_COEF, opadp += MMX_COEF)
		{
			temp = *keyp++;
			*ipadp ^= temp;
			*opadp ^= temp;
		}
	}
	else
	while((unsigned char)(temp = *keyp++)) {
		if (!(temp & 0xff00) || !(temp & 0xff0000))
		{
			*ipadp ^= (unsigned short)temp;
			*opadp ^= (unsigned short)temp;
			break;
		}
		*ipadp ^= temp;
		*opadp ^= temp;
		if (!(temp & 0xff000000))
			break;
		ipadp += MMX_COEF;
		opadp += MMX_COEF;
	}
#else
	int i;

	len = strlen(key);
	memcpy(saved_plain, key, len);
	saved_plain[len] = 0;

	memset(ipad, 0x36, PAD_SIZE);
	memset(opad, 0x5C, PAD_SIZE);

	if (len > PAD_SIZE) {
		MD5_CTX ctx;
		unsigned char k0[BINARY_SIZE];

		MD5_Init( &ctx );
		MD5_Update( &ctx, key, len);
		MD5_Final( k0, &ctx);

		len = BINARY_SIZE;

		for(i=0;i<len;i++)
		{
			ipad[i] ^= k0[i];
			opad[i] ^= k0[i];
		}
	}
	else
	for(i=0;i<len;i++)
	{
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
#endif
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	return saved_plain[index];
#else
	return saved_plain;
#endif
}

static int cmp_all(void *binary, int count)
{
#ifdef MMX_COEF
	unsigned int x,y=0;

#if MD5_SSE_PARA
	for(;y<MD5_SSE_PARA;y++)
#endif
		for(x=0;x<MMX_COEF;x++)
		{
			// NOTE crypt_key is in input format (64*MMX_COEF)
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*16] )
				return 1;
		}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count)
{
	return (1);
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		// NOTE crypt_key is in input format (64*MMX_COEF)
		if ( ((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[i*MMX_COEF+(index&3)+(index>>2)*16*MMX_COEF] )
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static void crypt_all(int count)
{
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	int i;
	SSEmd5body(ipad, ((unsigned int*)dump), 1);
	SSEmd5body(cursalt, ((unsigned int*)dump), 0);
	for (i = 0; i < MD5_SSE_PARA; ++i)
		memcpy(&crypt_key[64*MMX_COEF*i], &dump[BINARY_SIZE*MMX_COEF*i], BINARY_SIZE*MMX_COEF);

	SSEmd5body(opad, ((unsigned int*)dump), 1);
	SSEmd5body(crypt_key, ((unsigned int*)dump), 0);
	for (i = 0; i < MD5_SSE_PARA; ++i)
		memcpy(&crypt_key[64*MMX_COEF*i], &dump[BINARY_SIZE*MMX_COEF*i], BINARY_SIZE*MMX_COEF);
#else
	ARCH_WORD_32 total_len = ((ARCH_WORD_32*)cursalt)[14*MMX_COEF] >> 3;
	mdfivemmx_nosizeupdate( dump, ipad, 0);
	mdfivemmx_noinit_uniformsizeupdate( (unsigned char*) crypt_key, cursalt, total_len);

	mdfivemmx_nosizeupdate( dump, opad, 0);
	mdfivemmx_noinit_uniformsizeupdate( (unsigned char*) crypt_key, (unsigned char*) crypt_key, BINARY_SIZE + 64);
#endif
#else
	MD5_CTX ctx;

	MD5_Init( &ctx );
	MD5_Update( &ctx, ipad, PAD_SIZE );
	MD5_Update( &ctx, cursalt, strlen( (char*)cursalt) );
	MD5_Final( (unsigned char *) crypt_key, &ctx);

	MD5_Init( &ctx );
	MD5_Update( &ctx, opad, PAD_SIZE );
	MD5_Update( &ctx, crypt_key, BINARY_SIZE);
	MD5_Final( (unsigned char *) crypt_key, &ctx);
#endif
}

static void *binary(char *ciphertext)
{
	static unsigned char realcipher[BINARY_SIZE];
	int i,pos;

	for(i=strlen(ciphertext);ciphertext[i]!='#';i--); // allow # in salt
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];

	return (void*)realcipher;
}

static void *salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];
#ifdef MMX_COEF
	int i=0;
	int j;
	unsigned total_len=0;
#endif
	memset(salt, 0, sizeof(salt));
	// allow # in salt
	memcpy(salt, ciphertext, strrchr(ciphertext, '#') - ciphertext);
#ifdef MMX_COEF
	while(((unsigned char*)salt)[total_len])
	{
		for (i = 0; i < MD5_N; ++i)
			cursalt[GETPOS(total_len,i)] = ((unsigned char*)salt)[total_len];
		++total_len;
	}
	for (i = 0; i < MD5_N; ++i)
		cursalt[GETPOS(total_len, i)] = 0x80;
	for (j = total_len + 1; j < SALT_SIZE; ++j)
		for (i = 0; i < MD5_N; ++i)
			cursalt[GETPOS(j, i)] = 0;
	for (i = 0; i < MD5_N; ++i)
		((unsigned int *)cursalt)[14*MMX_COEF + (i&3) + (i>>2)*16*MMX_COEF] = (total_len+64)<<3;
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
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
