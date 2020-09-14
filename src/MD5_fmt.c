/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2001,2008,2010-2012,2017 by Solar Designer
 *
 * ...with changes in the jumbo patch, by bartavelle and magnum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "simd-intrinsics.h"
#include "MD5_std.h"
#include "common.h"
#include "formats.h"
#include "md5crypt_common.h"

#if defined(_OPENMP) && defined(SIMD_PARA_MD5)
#ifndef OMP_SCALE
#define OMP_SCALE			4
#endif
#include <omp.h>
#endif

#define FORMAT_LABEL			"md5crypt"
#define FORMAT_NAME			"crypt(3) $1$ (and variants)"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define PLAINTEXT_LENGTH		15
#define CIPHERTEXT_LENGTH		22

#ifdef SIMD_PARA_MD5
#define BINARY_SIZE			16
#else
#define BINARY_SIZE			4
#endif
#define BINARY_ALIGN			4
#define SALT_SIZE			9
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		MD5_N
#define MAX_KEYS_PER_CRYPT		MD5_N

static struct fmt_tests tests[] = {
	{"$1$12345678$aIccj83HRDBo6ux1bVx7D1", "0123456789ABCDE"},
	{"$1$7Uu2iTBB$Y4hQl2WvrOA3LBbLDxbAf0", "12345"},
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
	/* following hashes are AIX non-standard smd5 hashes */
	{"{smd5}s8/xSJ/v$uGam4GB8hOjTLQqvBfxJ2/", "password"},
	{"{smd5}alRJaSLb$aKM3H1.h1ycXl5GEVDH1e1", "aixsucks?"},
	{"{smd5}eLB0QWeS$Eg.YfWY8clZuCxF0xNrKg.", "0123456789ABCDE"},
	/* following hashes are AIX standard smd5 hashes (with corrected tag)
	 * lpa_options = std_hash=true */
	{"$1$JVDbGx8K$T9h8HK4LZxeLPMTAxCfpc1", "password"},
	{"$1$1Cu6fEvv$42kuaJ5fMEqyVStPuFG040", "0123456789ABCDE"},
	{"$1$27iyq7Ya$miN09fW1Scj0DHVNyewoU/", ""},
	{"$1$84Othc1n$v1cuReaa5lRdGuHaOa76n0", "a"},
	{"$1$4zq0BsCR$U2ua9WZtDEhzy4gFSiLxN1", "aa"},
	{"$1$DKwjKWxp$PY6PdlPZsXjOppPDoFOz4.", "aaa"},
	{"$1$OKDV6ppN$viTVmH48bSePiCrMvXT/./", "aaaa"},
	{"$1$QEWsCY0O$xrTTMKTepiHMp7Oxgz0pX/", "aaaaa"},
	{"$1$5dfdk2dF$XiJBPNrfKcCgdQ/kcoB40/", "aaaaaa"},
	{"$1$Ps6A1Cy6$WsvLg9cQhm9JU0rXkLEtz.", "aaaaaaa"},
	{"$1$9IK7nZ4M$4nx7Mdj05KGPJX/mZaDrh.", "aaaaaaaa"},
	{"$1$l3pNTqwT$GAc.dcRaxCvC20CFGCjp4/", "aaaaaaaaa"},
	{"$1$jSAARhJR$6daQ/ekjAL0MgOUgGJyp10", "aaaaaaaaaa"},
	{"$1$wk3Xwqqg$2AtdiucwJvJgbaVT1jWpb0", "aaaaaaaaaaa"},
	{"$1$G6Fn69Ei$d7AKJUOIdz/gO4Utc0TQP1", "aaaaaaaaaaaa"},
	{"$1$A7XJ7lGK$W5jTnH/4lW4XwZ.6F7n1N.", "aaaaaaaaaaaaa"},
	{"$1$Rcm46RfA$LfdIK/OP16yHzMYHSlx/B.", "aaaaaaaaaaaaaa"},
	{"$1$4bCSSJMN$TcYKTsukD4SFJE1n4MwMZ/", "aaaaaaaaaaaaaaa"},
#if PLAINTEXT_LENGTH > 15
	{"$1$mJxBkkl8$u7OHfWCPmNxvf0um7hH89.", "aaaaaaaaaaaaaaaa"},
	{"$1$Ub1gBUt4$TNaLxU7Pq5mk/MiDEb60b/", "aaaaaaaaaaaaaaaaa"},
	{"$1$8ot7QScR$x.p4vjIgdFxxS83x29PkJ0", "aaaaaaaaaaaaaaaaaa"},
	{"$1$wRi4OjD3$eJjKD2AwLMWfOTRYA30zn.", "aaaaaaaaaaaaaaaaaaa"},
	{"$1$lmektrsg$2KSRY4EUFzsYNMg80fG4/0", "aaaaaaaaaaaaaaaaaaaa"},
	{"$1$tgVBKBmE$YRvzsi7qHP2MC1Atg8VCV.", "aaaaaaaaaaaaaaaaaaaaa"},
	{"$1$oTsk88YC$Eh435T1BQzmjQekfqkHof/", "aaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$ykxSZEfP$hJrFeGOFk049L.94Mgggj/", "aaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$LBK4p5tD$5/gAIx8/7hpTVwDC/.KQv/", "aaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$fkEasaUI$G7CelOWHkol2nVHN8XQP40", "aaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$gRevVzeY$eMMQrsl5OHL5dP1p/ktJc/", "aaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$164TNEjj$ppoV6Ju6Vu63j1OlM4zit/", "aaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$ErPmhjp2$lZZstb2M455Xhk50eeH4i/", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$NUssS5fT$QaS4Ywt0IwzxbE0FAGnXn0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$NxlTyiJ7$gxkXTEJdeTzY8P6tqKmcz.", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$Cmy9x7gW$kamvHI42Kh1CH4Shy6g6S/", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$IsuapfCX$4Yq0Adq5nNZgl0LwbSl5Y0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	{"$1$rSZfNcKX$N4XPvGrfhKsyoEcRSaqmG0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
#endif
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
#ifdef SIMD_PARA_MD5
static unsigned char cursalt[SALT_SIZE];
static int CryptType;
static MD5_word (*sout);
static int omp_para = 1;
#endif

static void init(struct fmt_main *self)
{
	MD5_std_init(self);
#if defined(_OPENMP) && defined(SIMD_PARA_MD5)
	omp_para = omp_get_max_threads();
	if (omp_para < 1)
		omp_para = 1;
	self->params.min_keys_per_crypt = MD5_N * omp_para;
	omp_para *= OMP_SCALE;
	self->params.max_keys_per_crypt = MD5_N * omp_para;
#elif MD5_std_mt
	self->params.min_keys_per_crypt = MD5_std_min_kpc;
	self->params.max_keys_per_crypt = MD5_std_max_kpc;
#endif

	saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*saved_key), MEM_ALIGN_CACHE);
#ifdef SIMD_PARA_MD5
	sout = mem_calloc(self->params.max_keys_per_crypt,
	                  sizeof(*sout) * BINARY_SIZE);
#endif
}

static void done(void)
{
#ifdef SIMD_PARA_MD5
	MEM_FREE(sout);
#endif
	MEM_FREE(saved_key);
}

static int get_hash_0(int index)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	return ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] & PH_MASK_0;
#else
	init_t();
	return MD5_out[index][0] & PH_MASK_0;
#endif
}

static int get_hash_1(int index)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	return ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] & PH_MASK_1;
#else
	init_t();
	return MD5_out[index][0] & PH_MASK_1;
#endif
}

static int get_hash_2(int index)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	return ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] & PH_MASK_2;
#else
	init_t();
	return MD5_out[index][0] & PH_MASK_2;
#endif
}

static int get_hash_3(int index)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	return ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] & PH_MASK_3;
#else
	init_t();
	return MD5_out[index][0] & PH_MASK_3;
#endif
}

static int get_hash_4(int index)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	return ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] & PH_MASK_4;
#else
	init_t();
	return MD5_out[index][0] & PH_MASK_4;
#endif
}

static int get_hash_5(int index)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	return ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] & PH_MASK_5;
#else
	init_t();
	return MD5_out[index][0] & PH_MASK_5;
#endif
}

static int get_hash_6(int index)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	return ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] & PH_MASK_6;
#else
	init_t();
	return MD5_out[index][0] & PH_MASK_6;
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
#ifndef SIMD_PARA_MD5
	MD5_std_set_key(key, index);
#endif

	strnfcpy(saved_key[index], key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	saved_key[index][PLAINTEXT_LENGTH] = 0;

	return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#ifdef SIMD_PARA_MD5
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
	return count;
}

static int cmp_all(void *binary, int count)
{
#ifdef SIMD_PARA_MD5
	unsigned int x,y;

	for (y=0;y<SIMD_PARA_MD5*omp_para;y++) for (x=0;x<SIMD_COEF_32;x++)
	{
		if ( ((MD5_word *)binary)[0] == ((MD5_word *)sout)[x+y*SIMD_COEF_32*4] )
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
#ifdef SIMD_PARA_MD5
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;

	if (((unsigned int*)binary)[0] != ((unsigned int*)sout)[x+y*SIMD_COEF_32*4+0*SIMD_COEF_32])
		return 0;
	if (((unsigned int*)binary)[1] != ((unsigned int*)sout)[x+y*SIMD_COEF_32*4+1*SIMD_COEF_32])
		return 0;
	if (((unsigned int*)binary)[2] != ((unsigned int*)sout)[x+y*SIMD_COEF_32*4+2*SIMD_COEF_32])
		return 0;
	if (((unsigned int*)binary)[3] != ((unsigned int*)sout)[x+y*SIMD_COEF_32*4+3*SIMD_COEF_32])
		return 0;
	return 1;
#else
	init_t();
	return *(MD5_word *)binary == MD5_out[index][0];
#endif
}

static int cmp_exact(char *source, int index)
{
#ifdef SIMD_PARA_MD5
	return 1;
#else
	init_t();
	return !memcmp(MD5_std_get_binary(source), MD5_out[index],
	    sizeof(MD5_binary));
#endif
}

static void set_salt(void *salt)
{
#ifdef SIMD_PARA_MD5
	memcpy(cursalt, salt, SALT_SIZE);
	CryptType = cursalt[8];
	cursalt[8] = 0;
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
		"MD5 " MD5_ALGORITHM_NAME,
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
#if MD5_std_mt || defined(SIMD_PARA_MD5)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{
			md5_salt_prefix,
			apr1_salt_prefix,
			smd5_salt_prefix
		},
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		cryptmd5_common_valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
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
