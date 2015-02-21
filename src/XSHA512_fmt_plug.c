/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2008,2011 by Solar Designer
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_XSHA512;
#elif FMT_REGISTERS_H
john_register_one(&fmt_XSHA512);
#else

#include "sha2.h"

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "johnswap.h"
#include "sse-intrinsics.h"

#ifdef _OPENMP
#include <omp.h>
#ifdef MMX_COEF_SHA512
#define OMP_SCALE               4096
#else
#define OMP_SCALE               64
#endif
#endif

#include "memdbg.h"

#define FORMAT_LABEL			"xsha512"
#define FORMAT_NAME			"Mac OS X 10.7"
#define ALGORITHM_NAME			"SHA512 " SHA512_ALGORITHM_NAME
#define FORMAT_TAG              "$LION$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG) - 1)


#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		107
#define CIPHERTEXT_LENGTH		136

#define BINARY_SIZE			64
#define BINARY_ALIGN			8
#define SALT_SIZE			4
#define SALT_ALIGN			sizeof(ARCH_WORD_32)

#ifdef MMX_COEF_SHA512
#define MIN_KEYS_PER_CRYPT      MMX_COEF_SHA512
#define MAX_KEYS_PER_CRYPT      MMX_COEF_SHA512
#define GETPOS(i, index)        ( (index&(MMX_COEF_SHA512-1))*8 + ((i)&(0xffffffff-7))*MMX_COEF_SHA512 + (7-((i)&7)) + (index>>(MMX_COEF_SHA512>>1))*SHA512_BUF_SIZ*MMX_COEF_SHA512*8 )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		0x100
#endif

#if ARCH_BITS >= 64 || defined(__SSE2__)
/* 64-bitness happens to correlate with faster memcpy() */
#define PRECOMPUTE_CTX_FOR_SALT
#else
#undef PRECOMPUTE_CTX_FOR_SALT
#endif

static struct fmt_tests tests[] = {
	{"bb0489df7b073e715f19f83fd52d08ede24243554450f7159dd65c100298a5820525b55320f48182491b72b4c4ba50d7b0e281c1d98e06591a5e9c6167f42a742f0359c7", "password"},
	{"$LION$74911f723bd2f66a3255e0af4b85c639776d510b63f0b939c432ab6e082286c47586f19b4e2f3aab74229ae124ccb11e916a7a1c9b29c64bd6b0fd6cbd22e7b1f0ba1673", "hello"},
	{"$LION$5e3ab14c8bd0f210eddafbe3c57c0003147d376bf4caf75dbffa65d1891e39b82c383d19da392d3fcc64ea16bf8203b1fc3f2b14ab82c095141bb6643de507e18ebe7489", "boobies"},
	{NULL}
};

#ifdef MMX_COEF_SHA512
#define GETPOS(i, index)        ( (index&(MMX_COEF_SHA512-1))*8 + ((i)&(0xffffffff-7))*MMX_COEF_SHA512 + (7-((i)&7)) + (index>>(MMX_COEF_SHA512>>1))*SHA512_BUF_SIZ*MMX_COEF_SHA512*8 )
static ARCH_WORD_64 (*saved_key)[SHA512_BUF_SIZ*MMX_COEF_SHA512];
static ARCH_WORD_64 (*crypt_out)[8*MMX_COEF_SHA512];
static int max_keys;
#else
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static int (*saved_key_length);
static ARCH_WORD_32 (*crypt_out)[16];
#ifdef PRECOMPUTE_CTX_FOR_SALT
static SHA512_CTX ctx_salt;
#else
static ARCH_WORD_32 saved_salt;
#endif
#endif


static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef MMX_COEF_SHA512
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt/MMX_COEF_SHA512, MEM_ALIGN_SIMD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt/MMX_COEF_SHA512, MEM_ALIGN_SIMD);
	max_keys = self->params.max_keys_per_crypt;
#else
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key_length = mem_calloc_tiny(sizeof(*saved_key_length) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	/* Require lowercase hex digits (assume ASCII) */
	pos = ciphertext;
	if (strncmp(pos, FORMAT_TAG, TAG_LENGTH))
		return 0;
	pos += 6;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && (*pos <= '9' || *pos >= 'a'))
		pos++;
	return !*pos && pos - ciphertext == CIPHERTEXT_LENGTH+6;
}

static char *prepare(char *split_fields[10], struct fmt_main *self) {
	char Buf[200];
	if (!strncmp(split_fields[1], FORMAT_TAG, TAG_LENGTH))
		return split_fields[1];
	if (split_fields[0] && strlen(split_fields[0]) == CIPHERTEXT_LENGTH) {
		sprintf(Buf, "%s%s", FORMAT_TAG, split_fields[0]);
		if (valid(Buf, self)) {
			char *cp = mem_alloc_tiny(CIPHERTEXT_LENGTH+7, MEM_ALIGN_NONE);
			strcpy(cp, Buf);
			return cp;
		}
	}
	if (strlen(split_fields[1]) == CIPHERTEXT_LENGTH) {
		sprintf(Buf, "%s%s", FORMAT_TAG, split_fields[1]);
		if (valid(Buf, self)) {
			char *cp = mem_alloc_tiny(CIPHERTEXT_LENGTH+7, MEM_ALIGN_NONE);
			strcpy(cp, Buf);
			return cp;
		}
	}
	return split_fields[1];
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE];
		ARCH_WORD_64 dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	ciphertext += 6;
	p = ciphertext + 8;
	for (i = 0; i < sizeof(buf.c); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
#ifdef MMX_COEF_SHA512
	alter_endianity_to_BE64 (out, BINARY_SIZE/8);
#endif
	return out;
}

static void *salt(char *ciphertext)
{
	static union {
		unsigned char c[SALT_SIZE];
		ARCH_WORD_32 dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	int i;

	ciphertext += TAG_LENGTH;
	p = ciphertext;
	for (i = 0; i < sizeof(buf.c); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

#ifdef MMX_COEF_SHA512
static int get_hash_0 (int index) { return crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xf; }
static int get_hash_1 (int index) { return crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xff; }
static int get_hash_2 (int index) { return crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xfff; }
static int get_hash_3 (int index) { return crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xffff; }
static int get_hash_4 (int index) { return crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xfffff; }
static int get_hash_5 (int index) { return crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0xffffff; }
static int get_hash_6 (int index) { return crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return crypt_out[index][0] & 0xf; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xff; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xfff; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xffff; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xfffff; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xffffff; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7ffffff; }
#endif

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32 *)salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
#ifndef MMX_COEF_SHA512
#ifdef PRECOMPUTE_CTX_FOR_SALT
	SHA512_Init(&ctx_salt);
	SHA512_Update(&ctx_salt, salt, SALT_SIZE);
#else
	saved_salt = *(ARCH_WORD_32 *)salt;
#endif
#else
	int i;
	unsigned char *wucp = (unsigned char*)saved_key;
	for (i = 0; i < max_keys; ++i) {
		wucp[GETPOS(0, i)] = ((char*)salt)[0];
		wucp[GETPOS(1, i)] = ((char*)salt)[1];
		wucp[GETPOS(2, i)] = ((char*)salt)[2];
		wucp[GETPOS(3, i)] = ((char*)salt)[3];
	}
#endif
}

static void set_key(char *key, int index)
{
#ifndef MMX_COEF_SHA512
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	saved_key_length[index] = length;
	memcpy(saved_key[index], key, length);
#else
	// ok, first 4 bytes (if there are that many or more), we handle one offs.
	// this is because we already have 4 byte salt loaded into our saved_key.
	// IF there are more bytes of password, we drop into the multi loader.
	const ARCH_WORD_64 *wkey = (ARCH_WORD_64*)&(key[4]);
	ARCH_WORD_64 *keybuffer = &((ARCH_WORD_64 *)saved_key)[(index&(MMX_COEF_SHA512-1)) + (index>>(MMX_COEF_SHA512>>1))*SHA512_BUF_SIZ*MMX_COEF_SHA512 + MMX_COEF_SHA512];
	ARCH_WORD_64 *keybuf_word = keybuffer;
	unsigned int len;
	ARCH_WORD_64 temp;
	unsigned char *wucp = (unsigned char*)saved_key;
	len = 4;
	if (key[0] == 0) {wucp[GETPOS(4, index)] = 0x80; wucp[GETPOS(5, index)] = wucp[GETPOS(6, index)] = wucp[GETPOS(7, index)] = 0; goto key_cleaning; }
	wucp[GETPOS(4, index)] = key[0];
	++len;
	if (key[1] == 0) {wucp[GETPOS(5, index)] = 0x80; wucp[GETPOS(6, index)] = wucp[GETPOS(7, index)] = 0; goto key_cleaning; }
	wucp[GETPOS(5, index)] = key[1];
	++len;
	if (key[2] == 0) {wucp[GETPOS(6, index)] = 0x80; wucp[GETPOS(7, index)] = 0; goto key_cleaning; }
	wucp[GETPOS(6, index)] = key[2];
	++len;
	if (key[2] == 0) {wucp[GETPOS(7, index)] = 0x80;}
	wucp[GETPOS(7, index)] = key[3];
	++len;

	while((unsigned char)(temp = *wkey++)) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffff) | (0x80ULL << 24));
			len+=3;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffff) | (0x80ULL << 32));
			len+=4;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffULL) | (0x80ULL << 40));
			len+=5;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffffULL) | (0x80ULL << 48));
			len+=6;
			goto key_cleaning;
		}
		if (!(temp & 0xff00000000000000ULL))
		{
			*keybuf_word = JOHNSWAP64((temp & 0xffffffffffffffULL) | (0x80ULL << 56));
			len+=7;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP64(temp);
		len += 8;
		keybuf_word += MMX_COEF_SHA512;
	}
	*keybuf_word = 0x8000000000000000ULL;
key_cleaning:
	keybuf_word += MMX_COEF_SHA512;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF_SHA512;
	}
	keybuffer[14*MMX_COEF_SHA512] = len << 3;
#endif
}

static char *get_key(int index)
{
#ifndef MMX_COEF_SHA512
	saved_key[index][saved_key_length[index]] = 0;
	return saved_key[index];
#else
	static unsigned char key[PLAINTEXT_LENGTH+1];
	int i;
	unsigned char *wucp = (unsigned char*)saved_key;
	for (i = 0; i < PLAINTEXT_LENGTH; ++i) {
		key[i] = wucp[GETPOS(4+i, index)];
		if (key[i] == 0x80) {
			key[i] = 0;
			return (char*)key;
		}
	}
	key[i] = 0;
	return (char*)key;
#endif
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i;
#ifdef MMX_COEF_SHA512
	int inc = MMX_COEF_SHA512;
#else
	int inc = 1;
#endif
#ifdef _OPENMP
#ifndef MMX_COEF_SHA512
#ifdef PRECOMPUTE_CTX_FOR_SALT
#pragma omp parallel for default(none) private(i) shared(ctx_salt, count, saved_key, saved_key_length, crypt_out)
#else
#pragma omp parallel for default(none) private(i) shared(saved_salt, count, saved_key, saved_key_length, crypt_out)
#endif
#else
#pragma omp parallel for
#endif
#endif
	for (i = 0; i < count; i += inc) {
#ifdef MMX_COEF_SHA512
		SSESHA512body(&saved_key[i/MMX_COEF_SHA512], crypt_out[i/MMX_COEF_SHA512], NULL, SSEi_MIXED_IN);
#else
		SHA512_CTX ctx;
#ifdef PRECOMPUTE_CTX_FOR_SALT
		memcpy(&ctx, &ctx_salt, sizeof(ctx));
#else
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, &saved_salt, SALT_SIZE);
#endif
		SHA512_Update(&ctx, saved_key[i], saved_key_length[i]);
		SHA512_Final((unsigned char *)(crypt_out[i]), &ctx);
#endif
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
#ifdef MMX_COEF_SHA512
        if (((ARCH_WORD_64 *) binary)[0] == crypt_out[index>>(MMX_COEF_SHA512>>1)][index&(MMX_COEF_SHA512-1)])
#else
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_out[index][0] )
#endif
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF_SHA512
    int i;
	for (i = 0; i < BINARY_SIZE/sizeof(ARCH_WORD_64); i++)
        if (((ARCH_WORD_64 *) binary)[i] != crypt_out[index>>(MMX_COEF_SHA512>>1)][(index&(MMX_COEF_SHA512-1))+i*MMX_COEF_SHA512])
            return 0;
	return 1;
#else
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_XSHA512 = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		tests
	}, {
		init,
		fmt_default_done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
