/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#include <stdio.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "escrypt/crypto_scrypt.h"

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "base64.h"
#include "memdbg.h"

#define FORMAT_LABEL			"scrypt"
#define FORMAT_NAME			""
#define FMT_CISCO9              "$9$"
#ifdef __XOP__
#define ALGORITHM_NAME			"Salsa20/8 128/128 XOP"
#elif defined(__AVX__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 AVX"
#elif defined(__SSE2__)
#define ALGORITHM_NAME			"Salsa20/8 128/128 SSE2"
#else
#define ALGORITHM_NAME			"Salsa20/8 32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		" (16384, 8, 1)"
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		125

#define BINARY_SIZE			128
#define BINARY_ALIGN			1
#define SALT_SIZE			BINARY_SIZE
#define SALT_ALIGN			1

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests tests[] = {
	{"$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D", "pleaseletmein"},
	{"$7$C6..../....\x01\x09\x0a\x0d\x20\x7f\x80\xff$b7cKqzsQk7txdc9As1WZBHjUPNWQWJW8A.UUUTA5eD1", "\x01\x09\x0a\x0d\x20\x7f\x80\xff"},
	{"$7$2/..../....$rNxJWVHNv/mCNcgE/f6/L4zO6Fos5c2uTzhyzoisI62", ""},
	{"$7$86....E....NaCl$xffjQo7Bm/.SKRS4B2EuynbOLjAmXU5AbDbRXhoBl64", "password"},
	// cisco type 9 hashes.  .  They are $7$C/..../.... type  (N=16384, r=1, p=1) different base-64 (same as WPA).  salt used RAW
	{"$9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM", "cisco"},
	{"$9$cvWdfQlRRDKq/U$VFTPha5VHTCbSgSUAo.nPoh50ZiXOw1zmljEjXkaq1g", "123456"},
	{"$9$X9fA8mypebLFVj$Klp6X9hxNhkns0kwUIinvLRSIgWOvCwDhVTZqjsycyU", "JtR"},
	{NULL}
};

static int max_threads;
static escrypt_local_t *local;

static char saved_salt[SALT_SIZE];
static struct {
	char key[PLAINTEXT_LENGTH + 1];
	char out[BINARY_SIZE];
} *buffer;

static void init(struct fmt_main *self)
{
	int i;

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
	self->params.min_keys_per_crypt *= max_threads;
	self->params.max_keys_per_crypt *= max_threads;
#else
	max_threads = 1;
#endif

	local = mem_alloc(sizeof(*local) * max_threads);
	for (i = 0; i < max_threads; i++)
		escrypt_init_local(&local[i]);

	buffer = mem_alloc(sizeof(*buffer) * self->params.max_keys_per_crypt);
}


 /********************************************************************************************
  * This code will 'byte swap' the base-64. OHHH how I despise Base-64 (JimF).  I know many
  * here coding JtR have a hard on for it. But the 8000 different methods of doing base-64,
  * and absolutely NOTHING that tells us just what the decode is, makes this encoding method
  * absolutely SUCK to handle.  Yes, base-16 makes larger files, BUT it is 100% trivial on
  * processing. You always know how to do it. The only nuance is case, and that is trival
  *******************************************************************************************/
static void base64_unmap_i(char *in_block) {
  int i;
  char *c;

  for(i=0; i<4; i++) {
    c = in_block + i;
    if(*c == '.') { *c = 0; continue; }
    if(*c == '/') { *c = 1; continue; }
    if(*c>='0' && *c<='9') { *c -= '0'; *c += 2; continue; }
    if(*c>='A' && *c<='Z') { *c -= 'A'; *c += 12; continue; }
    *c -= 'a'; *c += 38;
  }
}
static void base64_decode_i(const char *in, int inlen, unsigned char *out) {
  int i, done=0;
  unsigned char temp[4];

  for(i=0; i<inlen; i+=4) {
    memcpy(temp, in, 4);
    memset(out, 0, 3);
    base64_unmap_i((char*)temp);
    out[0] = ((temp[0]<<2) & 0xfc) | ((temp[1]>>4) & 3);
	done += 2;
	if (done >= inlen) return;
    out[1] = ((temp[1]<<4) & 0xf0) | ((temp[2]>>2) & 0xf);
	if (++done >= inlen) return;
    out[2] = ((temp[2]<<6) & 0xc0) | ((temp[3]   ) & 0x3f);
	++done;
    out += 3;
    in += 4;
  }
}
static void enc_base64_1_i(char *out, unsigned val, unsigned cnt) {
	while (cnt--) {
		unsigned v = val & 0x3f;
		val >>= 6;
		*out++ = itoa64[v];
	}
}
static void base64_encode_i(const unsigned char *in, int len, char *outy) {
	int mod = len%3, i;
	unsigned u;
	for (i = 0; i*4 < len; ++i) {
		u = (in[i*3] | (((unsigned)in[i*3+1])<<8)  | (((unsigned)in[i*3+2])<<16));
		if (i*4+4>len)
			enc_base64_1_i(outy, u, 4-mod);
		else
			enc_base64_1_i(outy, u, 4);
		outy += 4;
	}
}
static char *crypt64_to_crypt64_bs(const char *in, char *out, int len) {
	unsigned char Tmp[256];
	base64_decode_i(in, len, Tmp);
	base64_encode_i(Tmp, len, out);
	out[len] = 0;
	return out;
}
/******************************************************************************
 * end of base6 byte swapping crap,  UGG
 *****************************************************************************/

static char *prepare(char *fields[10], struct fmt_main *self)
{
	static char Buf[120];
	char tmp[44];

	if (strncmp(fields[1], FMT_CISCO9, 3) != 0)
		return fields[1];
	if (strlen(fields[1]) != 4+14+43)
		return fields[1];

	// cisco type 9 hashes.  .  They are $7$C/..../.... type  (N=16384, r=1, p=1) different base-64 (same as WPA).  salt used RAW
//	{"$9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM", "cisco"},
	// becomes
//  {"$7$C/..../....$nhEmQVczB7dqsO$AG.yl8LDCkiErlh4ttizmxYCXSiXYrNY6vKmLDKj/P4", "cisco"},
	// the signature changes, and the hash base-64 is converted.  That is IT.

	// We have to byte swap (I think) the base-64.
	sprintf (Buf, "$7$C/..../....%14.14s$%s", &(fields[1][3]), crypt64_to_crypt64_bs(&(fields[1][3+14+1]), tmp, 43));
	return Buf;
}

static void done(void)
{
	int i;

	for (i = 0; i < max_threads; i++)
		escrypt_free_local(&local[i]);

	MEM_FREE(local);
	MEM_FREE(buffer);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *p;
	int length;

	if (strncmp(ciphertext, "$7$", 3))
		return 0;

	for (p = ciphertext + 3; p < ciphertext + (3 + 1 + 5 + 5); p++)
		if (atoi64[ARCH_INDEX(*p)] == 0x7F)
			return 0;

	p = strrchr(ciphertext, '$');
	if (!p)
		return 0;

	if (p - ciphertext > BINARY_SIZE - (1 + 43))
		return 0;

	length = 0;
	while (atoi64[ARCH_INDEX(*++p)] != 0x7F)
		length++;

	return !*p && length == 43;
}

static void *binary(char *ciphertext)
{
	static char out[BINARY_SIZE];
	strncpy(out, ciphertext, sizeof(out)); /* NUL padding is required */
	return out;
}

static void *salt(char *ciphertext)
{
	static char out[SALT_SIZE];
	char *p = strrchr(ciphertext, '$');
	/* NUL padding is required */
	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, p - ciphertext);
	return out;
}

#define H(s, i) \
	((int)(unsigned char)(atoi64[ARCH_INDEX((s)[(i)])] ^ (s)[(i) - 1]))

#define H0(s) \
	int i = strlen(s) - 2; \
	return i > 0 ? H((s), i) & 0xF : 0
#define H1(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 4)) & 0xFF : 0
#define H2(s) \
	int i = strlen(s) - 2; \
	return i > 2 ? (H((s), i) ^ (H((s), i - 2) << 6)) & 0xFFF : 0
#define H3(s) \
	int i = strlen(s) - 2; \
	return i > 4 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10)) & 0xFFFF : 0
#define H4(s) \
	int i = strlen(s) - 2; \
	return i > 6 ? (H((s), i) ^ (H((s), i - 2) << 5) ^ \
	    (H((s), i - 4) << 10) ^ (H((s), i - 6) << 15)) & 0xFFFFF : 0

static int binary_hash_0(void *binary)
{
	H0((char *)binary);
}

static int binary_hash_1(void *binary)
{
	H1((char *)binary);
}

static int binary_hash_2(void *binary)
{
	H2((char *)binary);
}

static int binary_hash_3(void *binary)
{
	H3((char *)binary);
}

static int binary_hash_4(void *binary)
{
	H4((char *)binary);
}

static int get_hash_0(int index)
{
	H0(buffer[index].out);
}

static int get_hash_1(int index)
{
	H1(buffer[index].out);
}

static int get_hash_2(int index)
{
	H2(buffer[index].out);
}

static int get_hash_3(int index)
{
	H3(buffer[index].out);
}

static int get_hash_4(int index)
{
	H4(buffer[index].out);
}

static int salt_hash(void *salt)
{
	int i, h;

	i = strlen((char *)salt) - 1;
	if (i > 1) i--;

	h = (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i])];
	h ^= ((unsigned char *)salt)[i - 1];
	h <<= 6;
	h ^= (unsigned char)atoi64[ARCH_INDEX(((char *)salt)[i - 1])];
	h ^= ((unsigned char *)salt)[i];

	return h & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	strcpy(saved_salt, salt);
}

static void set_key(char *key, int index)
{
	strnzcpy(buffer[index].key, key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return buffer[index].key;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int index;
	int failed = 0;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) shared(count, failed, local, saved_salt, buffer)
#endif
	for (index = 0; index < count; index++) {
		uint8_t *hash;
		hash = escrypt_r(&(local[index]),
		    (const uint8_t *)(buffer[index].key),
		    strlen(buffer[index].key),
		    (const uint8_t *)saved_salt,
		    (uint8_t *)&(buffer[index].out),
		    sizeof(buffer[index].out));
		if (!hash) {
			failed = 1;
			buffer[index].out[0] = 0;
		}
	}

	if (failed) {
		fprintf(stderr, "scrypt memory allocation failed\n");
		error();
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (!strcmp((char *)binary, buffer[index].out))
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !strcmp((char *)binary, buffer[index].out);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

#if FMT_MAIN_VERSION > 11
/*
 * FIXME: q&d implementation for now
 *
 *        Problems: -copied decode64_one() and decode64_uint32()
 *                   from escrypt/crypto_scrypt-common.c
 *                   (Copyright 2013 Alexander Peslyak)
 *                  -much of the logic in tunable_cost_[N|r|p] is identical
 *                   and copied/adapted from escrypt_r() in 
 *                   escrypt/crypto_scrypt-common.c
 *                   (Copyright 2013 Alexander Peslyak)
 */

static int decode64_one(uint32_t * dst, uint8_t src)
{
	/* FIXME: copied from escrypt/crypto_scrypt-common.c */
	const char * ptr = strchr(itoa64, src);
	if (ptr) {
		*dst = ptr - itoa64;
		return 0;
	}
	*dst = 0;
	return -1;
}

static const uint8_t * decode64_uint32(uint32_t * dst, uint32_t dstbits,
    const uint8_t * src)
{
	/* FIXME: copied from escrypt/crypto_scrypt-common.c */
	uint32_t bit;
	uint32_t value;

	value = 0;
	for (bit = 0; bit < dstbits; bit += 6) {
		uint32_t one;
		if (decode64_one(&one, *src)) {
			*dst = 0;
			return NULL;
		}
		src++;
		value |= one << bit;
	}

	*dst = value;
	return src;
}

static unsigned int tunable_cost_N(void *salt)
{
	const uint8_t * setting;
	const uint8_t * src;
	uint64_t N;

	setting = salt;
	if (setting[0] != '$' || setting[1] != '7' || setting[2] != '$')
		return 0;
	src = setting + 3;
	{
		uint32_t N_log2;

		if (decode64_one(&N_log2, *src))
			return 0;
		src++;
		N = (uint64_t)1 << N_log2;
	}

	return (unsigned int) N;
}
static unsigned int tunable_cost_r(void *salt)
{
	const uint8_t * setting;
	const uint8_t * src;
	uint32_t r;

	setting = salt;
	if (setting[0] != '$' || setting[1] != '7' || setting[2] != '$')
		return 0;
	src = setting + 3;
	{
		uint32_t N_log2;

		if (decode64_one(&N_log2, *src))
			return 0;
		src++;
	}
	src = decode64_uint32(&r, 30, src);
	if (!src)
		return 0;

	return (unsigned int) r;
}

static unsigned int tunable_cost_p(void *salt)
{
	const uint8_t * setting;
	const uint8_t * src;
	uint32_t r, p;

	setting = salt;
	if (setting[0] != '$' || setting[1] != '7' || setting[2] != '$')
		return 0;
	src = setting + 3;
	{
		uint32_t N_log2;

		if (decode64_one(&N_log2, *src))
			return 0;
		src++;
	}
	src = decode64_uint32(&r, 30, src);
	if (!src)
		return 0;
	src = decode64_uint32(&p, 30, src);
	if (!src)
		return 0;

	return (unsigned int) p;
}
#endif

struct fmt_main fmt_scrypt = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{
			"N",
			"r",
			"p"
		},
#endif
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
#if FMT_MAIN_VERSION > 11
		{
			tunable_cost_N,
			tunable_cost_r,
			tunable_cost_p
		},
#endif
		fmt_default_source,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			NULL,
			NULL
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
			NULL,
			NULL
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
