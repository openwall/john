/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010,2011 by Solar Designer
 *
 * ...with changes in the jumbo patch, by bartavelle
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#include "sse-intrinsics.h"
#include "MD5_std.h"

#if defined(_OPENMP) && defined(MD5_SSE_PARA)
#define OMP_SCALE			4
#include <omp.h>
#endif

#define FORMAT_LABEL			"md5"
#define FORMAT_NAME			"FreeBSD MD5"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		15
#define CIPHERTEXT_LENGTH		22

#ifdef MD5_SSE_PARA
#define BINARY_SIZE			16
#else
#define BINARY_SIZE			4
#endif
#define SALT_SIZE			9

#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N

static struct fmt_tests tests[] = {
	{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"$apr1$Q6ZYh...$RV6ft2bZ8j.NGrxLYaJt9.", "test"},
	{"$1$12345678$f8QoJuo0DpBRfQSD0vglc1", "12345678"},
	{"$1$$qRPK7m23GJusamGpoGLby/", ""},
	{"$apr1$a2Jqm...$grFrwEgiQleDr0zR4Jx1b.", "15 chars is max"},
	{"$1$$AuJCr07mI7DSew03TmBIv/", "no salt"},
	{"$1$`!@#%^&*$E6hD76/pKTS8qToBCkux30", "invalid salt"},
	{"$1$12345678$xek.CpjQUVgdf/P2N9KQf/", ""},
	{"$1$1234$BdIMOAWFOV2AQlLsrN/Sw.", "1234"},
	{"$apr1$rBXqc...$NlXxN9myBOk95T0AyLAsJ0", "john"},
	{"$apr1$Grpld/..$qp5GyjwM2dnA5Cdej9b411", "the"},
	{"$apr1$GBx.D/..$yfVeeYFCIiEXInfRhBRpy/", "ripper"},
	{"$1$bb$19smCEBG0Q1pVil0/HqK./", "aaaaa"},
	{"$1$coin$rebm0t9KJ56mgGWJF5o5M0", "lapin"},
	{"$1$pouet$/Ecz/vyk.zCYvrr6wB78h0", "canard"},
	{"$1$test2$02MCIATVoxq3IhgK6XRkb1", "test1"},
	{"$1$aussi$X67z3kXsWo92F15uChx1H1", "felicie"},
	{"$1$boire$gf.YM2y3InYEu9.NbVr.v0", "manger"},
	{"$1$bas$qvkmmWnVHRCSv/6LQ1doH/", "haut"},
	{"$1$gauche$EPvd6LZlrgb0MMFPxUrJN1", "droite"},
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
#ifdef MD5_SSE_PARA
static unsigned char cursalt[SALT_SIZE];
static int CryptType;
static MD5_word (*sout);
static int omp_para = 1;
#endif

static void init(struct fmt_main *pFmt)
{
	MD5_std_init(pFmt);
#if defined(_OPENMP) && defined(MD5_SSE_PARA)
	omp_para = omp_get_max_threads();
	if (omp_para < 1)
		omp_para = 1;
	pFmt->params.min_keys_per_crypt = MD5_N * omp_para;
	omp_para *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt = MD5_N * omp_para;
#elif MD5_std_mt
	pFmt->params.min_keys_per_crypt = MD5_std_min_kpc;
	pFmt->params.max_keys_per_crypt = MD5_std_max_kpc;
#endif

	saved_key = mem_calloc_tiny(
	    sizeof(*saved_key) * pFmt->params.max_keys_per_crypt,
	    MEM_ALIGN_CACHE);
#ifdef MD5_SSE_PARA
	sout = mem_calloc_tiny(sizeof(*sout) *
	                       pFmt->params.max_keys_per_crypt *
	                       BINARY_SIZE, sizeof(MD5_word));
#endif
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos, *start;

	if (strncmp(ciphertext, "$1$", 3)) {
		if (strncmp(ciphertext, "$apr1$", 6))
			return 0;
		ciphertext += 3;
	}

	for (pos = &ciphertext[3]; *pos && *pos != '$'; pos++);
	if (!*pos || pos < &ciphertext[3] || pos > &ciphertext[11]) return 0;

	start = ++pos;
	while (atoi64[ARCH_INDEX(*pos)] != 0x7F) pos++;
	if (*pos || pos - start != CIPHERTEXT_LENGTH) return 0;

	if (atoi64[ARCH_INDEX(*(pos - 1))] & 0x3C) return 0;

	return 1;
}

static int binary_hash_0(void *binary)
{
	return *(MD5_word *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(MD5_word *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(MD5_word *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(MD5_word *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(MD5_word *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(MD5_word *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(MD5_word *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((MD5_word *)sout)[x+y*MMX_COEF*4] & 0xF;
#else
	init_t();
	return MD5_out[index][0] & 0xF;
#endif
}

static int get_hash_1(int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((MD5_word *)sout)[x+y*MMX_COEF*4] & 0xFF;
#else
	init_t();
	return MD5_out[index][0] & 0xFF;
#endif
}

static int get_hash_2(int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((MD5_word *)sout)[x+y*MMX_COEF*4] & 0xFFF;
#else
	init_t();
	return MD5_out[index][0] & 0xFFF;
#endif
}

static int get_hash_3(int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((MD5_word *)sout)[x+y*MMX_COEF*4] & 0xFFFF;
#else
	init_t();
	return MD5_out[index][0] & 0xFFFF;
#endif
}

static int get_hash_4(int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((MD5_word *)sout)[x+y*MMX_COEF*4] & 0xFFFFF;
#else
	init_t();
	return MD5_out[index][0] & 0xFFFFF;
#endif
}

static int get_hash_5(int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((MD5_word *)sout)[x+y*MMX_COEF*4] & 0xFFFFFF;
#else
	init_t();
	return MD5_out[index][0] & 0xFFFFFF;
#endif
}

static int get_hash_6(int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;
	return ((MD5_word *)sout)[x+y*MMX_COEF*4] & 0x7FFFFFF;
#else
	init_t();
	return MD5_out[index][0] & 0x7FFFFFF;
#endif
}

static int salt_hash(void *salt)
{
	unsigned int i, h, retval;

	retval = 0;
	for (i = 0; i <= 6; i += 2) {
		h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
		h ^= ((unsigned char *)salt)[i + 1];
		h <<= 6;
		h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i + 1])];
		h ^= ((unsigned char *)salt)[i];
		retval += h;
	}

	retval ^= retval >> SALT_HASH_LOG;
	retval &= SALT_HASH_SIZE - 1;

	return retval;
}

static void set_key(char *key, int index)
{
#ifndef MD5_SSE_PARA
	MD5_std_set_key(key, index);
#endif

	strnfcpy(saved_key[index], key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	saved_key[index][PLAINTEXT_LENGTH] = 0;

	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;

	for(y=0;y<MD5_SSE_PARA*omp_para;y++) for(x=0;x<MMX_COEF;x++)
	{
		if( ((MD5_word *)binary)[0] == ((MD5_word *)sout)[x+y*MMX_COEF*4] )
			return 1;
	}
	return 0;
#else
#if MD5_std_mt
	int t, n = (count + (MD5_N - 1)) / MD5_N;
#endif
	for_each_t(n) {
#if MD5_X2
		if (*(MD5_word *)binary == MD5_out[0][0] ||
		    *(MD5_word *)binary == MD5_out[1][0])
			return 1;
#else
		if (*(MD5_word *)binary == MD5_out[0][0])
			return 1;
#endif
	}
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef MD5_SSE_PARA
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((unsigned int *)binary)[0] != ((unsigned int *)sout)[x+y*MMX_COEF*4] )
		return 0;
	if( ((unsigned int *)binary)[1] != ((unsigned int *)sout)[x+y*MMX_COEF*4+4] )
		return 0;
	if( ((unsigned int *)binary)[2] != ((unsigned int *)sout)[x+y*MMX_COEF*4+8] )
		return 0;
	if( ((unsigned int *)binary)[3] != ((unsigned int *)sout)[x+y*MMX_COEF*4+12] )
		return 0;
	return 1;
#else
	init_t();
	return *(MD5_word *)binary == MD5_out[index][0];
#endif
}

static int cmp_exact(char *source, int index)
{
#ifdef MD5_SSE_PARA
	return 1;
#else
	init_t();
	return !memcmp(MD5_std_get_binary(source), MD5_out[index],
	    sizeof(MD5_binary));
#endif
}

static void crypt_all(int count) {
#ifdef MD5_SSE_PARA
#ifdef _OPENMP
	int t;
#pragma omp parallel for
	for (t = 0; t < omp_para; t++)
		md5cryptsse((unsigned char *)(&saved_key[t*MD5_N]), cursalt, (char *)(&sout[t*MD5_N*BINARY_SIZE/sizeof(MD5_word)]), CryptType);
#else
	md5cryptsse((unsigned char *)saved_key, cursalt, (char *)sout, CryptType);
#endif
#else
	MD5_std_crypt(count);
#endif
}

static void set_salt(void *salt)
{
#ifdef MD5_SSE_PARA
	memcpy(cursalt, salt, SALT_SIZE);
	if (cursalt[8]) {
		CryptType = MD5_TYPE_APACHE;
		cursalt[8] = 0;
	}
	else
		CryptType = MD5_TYPE_STD;
#endif
	MD5_std_set_salt(salt);
}

static void *get_salt(char *ciphertext) {
	return MD5_std_get_salt(ciphertext);
}

static void *get_binary(char *ciphertext) {
	return MD5_std_get_binary(ciphertext);
}

struct fmt_main fmt_MD5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		MD5_ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if MD5_std_mt || defined(MD5_SSE_PARA)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
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
