/*
 * Mac OS X 10.7+ salted SHA-512 password hashing, CUDA interface.
 *
 * Copyright (c) 2008,2011 Solar Designer (original CPU-only code)
 * Copyright (c) 2012 myrice (interfacing to CUDA)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */


#include <string.h>

#include "cuda_xsha512.h"
#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"xsha512-cuda"
#define FORMAT_NAME			"Mac OS X 10.7+ salted SHA-512"
#define ALGORITHM_NAME			"CUDA"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0



static struct fmt_tests tests[] = {
	{"$LION$bb0489df7b073e715f19f83fd52d08ede24243554450f7159dd65c100298a5820525b55320f48182491b72b4c4ba50d7b0e281c1d98e06591a5e9c6167f42a742f0359c7", "password"},
	{"$LION$74911f723bd2f66a3255e0af4b85c639776d510b63f0b939c432ab6e082286c47586f19b4e2f3aab74229ae124ccb11e916a7a1c9b29c64bd6b0fd6cbd22e7b1f0ba1673", "hello"},
	{"5e3ab14c8bd0f210eddafbe3c57c0003147d376bf4caf75dbffa65d1891e39b82c383d19da392d3fcc64ea16bf8203b1fc3f2b14ab82c095141bb6643de507e18ebe7489", "boobies"},
	{NULL}
};

extern void cuda_xsha512(xsha512_key *host_password, xsha512_salt *host_salt, xsha512_hash* host_hash);
extern void cuda_xsha512_init();
extern int cuda_cmp_all(void *binary, int count);
extern void cuda_xsha512_cpy_hash(xsha512_hash* host_hash);



static xsha512_key *gkey;
static xsha512_hash *ghash;
static xsha512_salt gsalt;
uint8_t xsha512_key_changed;

static void init(struct fmt_main *pFmt)
{
	gkey = (xsha512_key*)malloc(sizeof(xsha512_key)*MAX_KEYS_PER_CRYPT);
	ghash = (xsha512_hash*)malloc(sizeof(xsha512_hash)*MAX_KEYS_PER_CRYPT);
	cuda_xsha512_init();
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *pos;

	/* Require lowercase hex digits (assume ASCII) */
	pos = ciphertext;
	if (strncmp(pos, "$LION$", 6))
		return 0;
	pos += 6;
	while (atoi16[ARCH_INDEX(*pos)] != 0x7F && (*pos <= '9' || *pos >= 'a'))
		pos++;
	return !*pos && pos - ciphertext == CIPHERTEXT_LENGTH+6;
}

static char *prepare(char *split_fields[10], struct fmt_main *pFmt) {
	char Buf[200];
	if (!strncmp(split_fields[1], "$LION$", 6))
		return split_fields[1];
	if (split_fields[0] && strlen(split_fields[0]) == CIPHERTEXT_LENGTH) {
		sprintf(Buf, "$LION$%s", split_fields[0]);
		if (valid(Buf, pFmt)) {
			char *cp = mem_alloc_tiny(CIPHERTEXT_LENGTH+7, MEM_ALIGN_NONE);
			strcpy(cp, Buf);
			return cp;
		}
	}
	if (strlen(split_fields[1]) == CIPHERTEXT_LENGTH) {
		sprintf(Buf, "$LION$%s", split_fields[1]);
		if (valid(Buf, pFmt)) {
			char *cp = mem_alloc_tiny(CIPHERTEXT_LENGTH+7, MEM_ALIGN_NONE);
			strcpy(cp, Buf);
			return cp;
		}
	}
	return split_fields[1];
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[BINARY_SIZE];
	char *p;
	int i;

	ciphertext += 6;
	p = ciphertext + 8;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static void *salt(char *ciphertext)
{
	static unsigned char out[SALT_SIZE];
	char *p;
	int i;

	ciphertext += 6;
	p = ciphertext;
	for (i = 0; i < sizeof(out); i++) {
		out[i] =
		    (atoi16[ARCH_INDEX(*p)] << 4) |
		    atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}

	return out;
}

static int binary_hash_0(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
	return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xF;
}

static int get_hash_1(int index)
{	
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFF;
}

static int get_hash_2(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFF;
}

static int get_hash_3(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFFF;
}

static int get_hash_4(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFFFF;
}

static int get_hash_5(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
	cuda_xsha512_cpy_hash(ghash);
	return ((uint64_t*)ghash)[hash_addr(0, index)] & 0x7FFFFFF;
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32 *)salt & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	memcpy(gsalt.v, (uint8_t*)salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	int length = strlen(key);
	if (length > PLAINTEXT_LENGTH)
		length = PLAINTEXT_LENGTH;
	gkey[index].length = length;
	memcpy(gkey[index].v, key, length);
	xsha512_key_changed = 1;
}

static char *get_key(int index)
{
	gkey[index].v[gkey[index].length] = 0;
	return gkey[index].v;
}

static void crypt_all(int count)
{
	cuda_xsha512(gkey, &gsalt, ghash);
	xsha512_key_changed = 0;
}

static int cmp_all(void *binary, int count)
{
	return cuda_cmp_all(binary, count);
}

static int cmp_one(void *binary, int index)
{
	int i;
	uint64_t *b = (uint64_t *) binary;
	cuda_xsha512_cpy_hash(ghash);
	uint64_t *t = (uint64_t *)ghash;
	for (i = 0; i < BINARY_SIZE / 8; i++) {
		if (b[i] != t[hash_addr(i, index)])
			return 0;
	}
	return 1;

}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_cuda_xsha512 = {
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
		tests
	}, {
		init,
		prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
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
