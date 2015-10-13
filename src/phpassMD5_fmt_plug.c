/*
 * This software was written by Jim Fougeron jfoug AT cox dot net in 2009.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain. In case this attempt to disclaim copyright and place the software in
 *  the public domain is deemed null and void, then the software is Copyright
 * (c) 2009 Jim Fougeron and it is hereby released to the general public under
 * the following terms:
 *
 * This software may be modified, redistributed, and used for any purpose,
 * in source and binary forms, with or without modification.
 *
 * Cracks phpass 'portable' hashes, and phpBBv3 hashes, which are simply phpass
 * portable, with a slightly different signature. These are 8 byte salted
 * hashes, with a 1 byte 'salt' that defines the number of loops to compute.
 * Internally we work with 8 byte salt (the 'real' salt), but let john track
 * it as 9 byte salts to also pass in the loop count.  Code works even if
 * multiple loop count values within the input. PHPv5 kicked up the loop
 * count, Wordpress uses same format, but even higher loop count. The loop
 * count can be used to 'tune' the format, by asking to process only
 * only hashes of a specific count.
 *
 * uses openSSL's MD5 and SIMD MD5.
 *
 * Code was pretty much rewritten to re-enable this format, and to deprecate
 * dynamic_17. It required ported to use the new intrisic SIMD code, including
 * AVX2, AVX2-512, and others, and the overall starting point for this older
 * code was pretty bad.  This port done August 2015, Jim Fougeron.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_phpassmd5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_phpassmd5);
#else


#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

//#undef _OPENMP
//#undef SIMD_COEF_32
//#undef SIMD_PARA_MD5

#ifdef _OPENMP
#define OMP_SCALE               1
#include <omp.h>
#endif

#include "simd-intrinsics.h"
#include "memdbg.h"

#define FORMAT_LABEL			"phpass"
#define FORMAT_NAME				""
#define ALGORITHM_NAME			"phpass ($P$ or $H$) "  MD5_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD5)
#endif

#define BENCHMARK_COMMENT		" ($P$9)"
#define BENCHMARK_LENGTH		-1 // only 1 salt is pretty much same speed.

#define PLAINTEXT_LENGTH		39
#define CIPHERTEXT_LENGTH		34
#ifndef MD5_BUF_SIZ
#define MD5_BUF_SIZ				16
#endif

#define BINARY_SIZE				16
#define DIGEST_SIZE				16
#define SALT_SIZE				8
// NOTE salts are only 8 bytes, but we tell john they are 9.
// We then take the 8 bytes of salt, and append the 1 byte of
// loop count data, making it 9.
#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT	NBKEYS
#define MAX_KEYS_PER_CRYPT	NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*MD5_BUF_SIZ*4*SIMD_COEF_32 )
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

static struct fmt_tests tests[] = {
		{"$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00", "test1"},
		{"$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1", "123456"},
		{"$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1", "123456"},
		{"$P$912345678LIjjb6PhecupozNBmDndU0", "thisisalongertestPW"},
		{"$H$9A5she.OeEiU583vYsRXZ5m2XIpI68/", "123456"},
		{"$P$917UOZtDi6ksoFt.y2wUYvgUI6ZXIK/", "test1"},
		{"$P$91234567AQwVI09JXzrV1hEC6MSQ8I0", "thisisalongertest"},
		{"$P$9234560A8hN6sXs5ir0NfozijdqT6f0", "test2"},
		{"$P$9234560A86ySwM77n2VA/Ey35fwkfP0", "test3"},
		{"$P$9234560A8RZBZDBzO5ygETHXeUZX5b1", "test4"},
		{"$P$91234567xogA.H64Lkk8Cx8vlWBVzH0", "thisisalongertst"},
		{"$P$612345678si5M0DDyPpmRCmcltU/YW/", "JohnRipper"}, // note smaller loop count
		{"$H$712345678WhEyvy1YWzT4647jzeOmo0", "JohnRipper"}, // note smaller loop count (phpbb w/older PHP version)
		{"$P$B12345678L6Lpt4BxNotVIMILOa9u81", "JohnRipper"}, // note larber loop count  (Wordpress)
		{NULL}
};

#ifdef SIMD_COEF_32
// hash with key appended (used on all steps other than first)
static ARCH_WORD_32 (*hash_key)[MD5_BUF_SIZ*NBKEYS];
// salt with key appended (only used in 1st step).
static ARCH_WORD_32 (*cursalt)[MD5_BUF_SIZ*NBKEYS];
static ARCH_WORD_32 (*crypt_key)[DIGEST_SIZE/4*NBKEYS];
static unsigned max_keys;
#else
static char (*crypt_key)[PLAINTEXT_LENGTH+1+BINARY_SIZE];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static unsigned (*saved_len);
static unsigned char cursalt[SALT_SIZE];
#endif
static unsigned loopCnt;

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	unsigned count_log2;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;
	// Handle both the phpass signature, and the phpBB v3 signature (same formula)
	// NOTE we are only dealing with the 'portable' encryption method
	if (strncmp(ciphertext, "$P$", 3) != 0 && strncmp(ciphertext, "$H$", 3) != 0)
		return 0;
	for (i = 3; i < CIPHERTEXT_LENGTH; ++i)
		if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
	if (count_log2 < 7 || count_log2 > 31)
		return 0;

	return 1;
}

static void init(struct fmt_main *self) {
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef SIMD_COEF_32
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*crypt_key), MEM_ALIGN_SIMD);
	hash_key = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*hash_key), MEM_ALIGN_SIMD);
	cursalt = mem_calloc_align(self->params.max_keys_per_crypt/NBKEYS,
	                             sizeof(*cursalt), MEM_ALIGN_SIMD);
	max_keys = self->params.max_keys_per_crypt;
#else
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
#endif
}

// convert dynamic_17 back into phpass format
char *split(char *ciphertext, int index, struct fmt_main *self)
{
	static char out[CIPHERTEXT_LENGTH + 1];
	char *cpH, *cpS;

	if (strncmp(ciphertext, "$dynamic_17$", 12))
		return ciphertext;
	cpH = ciphertext + 12;
	strcpy(out, "$P$");
	cpS = strchr(cpH, '$');
	if (!cpS)
		return ciphertext;
	++cpS;
	out[3] = cpS[8];
	memcpy(&out[4], cpS, 8);
	memcpy(&out[12], cpH, 22);
	return out;
}

char *prepare(char *split_fields[10], struct fmt_main *self)
{
	return split(split_fields[1], 0, self);
}

static void done(void)
{
	MEM_FREE(crypt_key);
#ifndef SIMD_COEF_32
	MEM_FREE(saved_len);
	MEM_FREE(saved_key);
#else
	MEM_FREE(hash_key);
	MEM_FREE(cursalt);
#endif
}

static void set_salt(void *salt)
{
#ifdef SIMD_COEF_32
	int i;
	ARCH_WORD_32 *p;

	p = cursalt[0];
	for (i = 0; i < max_keys; ++i) {
		if (i && (i&(SIMD_COEF_32-1)) == 0)
			p += 15*SIMD_COEF_32;
		p[0] = ((ARCH_WORD_32 *)salt)[0];
		p[SIMD_COEF_32] = ((ARCH_WORD_32 *)salt)[1];
		++p;
	}
#else	// !SIMD_COEF_32
	memcpy(cursalt, salt, 8);
#endif
	// compute the loop count for this salt
	loopCnt = (1 << (atoi64[ARCH_INDEX(((char*)salt)[8])]));
}

static void set_key(char *key, int index) {
#ifdef SIMD_COEF_32
	// in SIMD, we put the key into the cursalt (at offset 8),
	// and into hash_key (at offset 16). We also clean both
	// buffers, and put the 0x80, and the length into them.
	int len = strlen(key), i, j;
	unsigned char *co1 = (unsigned char*)cursalt;
	unsigned char *co2 = (unsigned char*)hash_key;

	for (i = 0; i < len; ++i) {
		// byte by byte. Slow but easy to follow, and the
		// speed here does not really matter.
		co1[GETPOS(i+8,index)] = key[i];
		co2[GETPOS(i+16,index)] = key[i];
	}
	// Place the end of string marker
	co1[GETPOS(i+8,index)] = 0x80;
	co2[GETPOS(i+16,index)] = 0x80;
	// clean out both buffers top parts.
	for (j = i+9; j < 56; ++j)
		co1[GETPOS(j,index)] = 0;
	for (j = i+17; j < 56; ++j)
		co2[GETPOS(j,index)] = 0;
	// set the length in bits of salt and hash
	co1[GETPOS(56,index)] = ((len+8)<<3)&0xFF;
	co2[GETPOS(56,index)] = ((len+16)<<3)&0xFF;
	co1[GETPOS(57,index)] = ((len+8)<<3)>>8;
	co2[GETPOS(57,index)] = ((len+16)<<3)>>8;
#else
	int len= strlen(key);
	saved_len[index]=len;
	strcpy(saved_key[index], key);
#endif
}

static char *get_key(int index) {
#ifdef SIMD_COEF_32
	unsigned char *saltb8 = (unsigned char*)cursalt;
	static char out[PLAINTEXT_LENGTH+1];
	int len, i;

	// get salt length (in bits)
	len = saltb8[GETPOS(57,index)];
	len <<= 8;
	len |= saltb8[GETPOS(56,index)];
	// convert to bytes.
	len >>= 3;
	// we skip the 8 bytes of salt (to get to password).
	len -= 8;
	// now grab the password.
	for (i = 0; i < len; ++i)
		out[i] = saltb8[GETPOS(8+i,index)];
	out[i] = 0;
	return out;
#else
	return saved_key[index];
#endif
}

static int cmp_all(void *binary, int count) {
	unsigned i = 0;

#ifdef SIMD_COEF_32
	ARCH_WORD_32 *p;
	ARCH_WORD_32 bin = *(ARCH_WORD_32 *)binary;

	p = crypt_key[0];
	for (i = 0; i < count; ++i) {
		if (i && (i&(SIMD_COEF_32-1)) == 0)
			p += 3*SIMD_COEF_32;
		if (bin == *p++)
			return 1;
	}
	return 0;
#else
	for (i = 0; i < count; i++)
		if (!memcmp(binary, crypt_key[i], BINARY_SIZE))
			return 1;
	return 0;
#endif
}

static int cmp_exact(char *source, int index)
{
		return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
	int idx = index&(SIMD_COEF_32-1);
	int off = (index/SIMD_COEF_32)*(4*SIMD_COEF_32);
	return((((ARCH_WORD_32 *)binary)[0] == ((ARCH_WORD_32 *)crypt_key)[off+0*SIMD_COEF_32+idx]) &&
	       (((ARCH_WORD_32 *)binary)[1] == ((ARCH_WORD_32 *)crypt_key)[off+1*SIMD_COEF_32+idx]) &&
	       (((ARCH_WORD_32 *)binary)[2] == ((ARCH_WORD_32 *)crypt_key)[off+2*SIMD_COEF_32+idx]) &&
	       (((ARCH_WORD_32 *)binary)[3] == ((ARCH_WORD_32 *)crypt_key)[off+3*SIMD_COEF_32+idx]));
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}


static int crypt_all(int *pcount, struct db_salt *salt) {
	const int count = *pcount;
	int loops = 1, index;

#ifdef _OPENMP
	loops = (count + MAX_KEYS_PER_CRYPT - 1) / MAX_KEYS_PER_CRYPT;
#pragma omp parallel for
#endif
	for (index = 0; index < loops; index++)
	{
		unsigned Lcount;
#ifdef SIMD_COEF_32

		SIMDmd5body(cursalt[index], hash_key[index], NULL, SSEi_OUTPUT_AS_INP_FMT);
		Lcount = loopCnt-1;
		do {
			SIMDmd5body(hash_key[index], hash_key[index], NULL, SSEi_OUTPUT_AS_INP_FMT);
		} while (--Lcount);
		// last hash goes into crypt_key
		SIMDmd5body(hash_key[index], crypt_key[index], NULL, 0);
#else
		MD5_CTX ctx;
		MD5_Init( &ctx );
		MD5_Update( &ctx, cursalt, 8 );
		MD5_Update( &ctx, saved_key[index], saved_len[index] );
		MD5_Final( (unsigned char *) crypt_key[index], &ctx);

		strcpy(((char*)&(crypt_key[index]))+BINARY_SIZE, saved_key[index]);
		Lcount = loopCnt;

		do {
			MD5_Init( &ctx );
			MD5_Update( &ctx, crypt_key[index],  BINARY_SIZE+saved_len[index]);
			MD5_Final( (unsigned char *)&(crypt_key[index]), &ctx);
		} while (--Lcount);
#endif
	}
	return count;
}

static void * binary(char *ciphertext)
{
	int i;
	unsigned sixbits;
	static unsigned char b[16];
	int bidx=0;
	char *pos;

	pos = &ciphertext[3+1+8];
	for (i = 0; i < 5; ++i)
	{
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<6);
		sixbits >>= 2;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<4);
		sixbits >>= 4;
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx++] |= (sixbits<<2);
	}
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] = sixbits;
	sixbits = atoi64[ARCH_INDEX(*pos++)];
	b[bidx] |= (sixbits<<6);
	return b;
}

static void * salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE+2];
	// store off the 'real' 8 bytes of salt
	memcpy(salt, &ciphertext[4], 8);
	// append the 1 byte of loop count information.
	salt[8] = ciphertext[3];
	salt[9]=0;
	return salt;
}

#ifdef SIMD_COEF_32
#define SIMD_INDEX (index&(SIMD_COEF_32-1))+(unsigned int)index/SIMD_COEF_32*SIMD_COEF_32*4
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_0; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_1; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_2; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_3; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_4; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_5; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[SIMD_INDEX] & PH_MASK_6; }
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32*)(crypt_key[index]))[0] & PH_MASK_0; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)(crypt_key[index]))[0] & PH_MASK_1; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)(crypt_key[index]))[0] & PH_MASK_2; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)(crypt_key[index]))[0] & PH_MASK_3; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)(crypt_key[index]))[0] & PH_MASK_4; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)(crypt_key[index]))[0] & PH_MASK_5; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)(crypt_key[index]))[0] & PH_MASK_6; }
#endif

static int salt_hash(void *salt)
{
	return *((ARCH_WORD *)salt) & 0x3FF;
}

static unsigned int iteration_count(void *salt)
{
	return 1U<<atoi64[(((unsigned char*)salt)[8])];
}

struct fmt_main fmt_phpassmd5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		4,
		SALT_SIZE+1,
		4,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#ifdef _OPENMP
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT,
		{
			"iteration count",
		},
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		split,
		binary,
		salt,
		{
			iteration_count,
		},
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

#endif /* plugin stanza */
