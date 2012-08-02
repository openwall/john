/*  HTTP Digest access authentication patch for john
 *
 * Written by Romain Raboin. OMP and intrinsics support by magnum
 *
 * This software is Copyright © 2008 Romain Raboin - romain.raboin at
 * gmail.com, and Copyright © 2012 magnum and it is hereby released to
 * the general public under the following terms:  Redistribution and
 * use in source and binary forms, with or without modification, are
 * permitted.
 */

#include <string.h>

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

#ifdef __MMX__
#include <mmintrin.h>
#endif

#include "arch.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

#include "stdint.h"

#ifdef MD5_SSE_PARA
#define MMX_COEF			4
#define NBKEYS				(MMX_COEF * MD5_SSE_PARA)
#elif defined(MMX_COEF)
#define NBKEYS				MMX_COEF
#endif
#include "sse-intrinsics.h"
#define ALGORITHM_NAME			MD5_ALGORITHM_NAME

#define FORMAT_LABEL			"hdaa"
#define FORMAT_NAME			"HTTP Digest access authentication MD5"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16

#if defined(_OPENMP) && (defined (MD5_SSE_PARA) || !defined(MMX_COEF))
#include <omp.h>
static unsigned int omp_t = 1;
#ifdef MD5_SSE_PARA
#define OMP_SCALE			256
#else
#define OMP_SCALE			64
#endif
#endif

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&60)*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*64*MMX_COEF )
#define GETOUTPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&0x1c)*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*16*MMX_COEF )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define SEPARATOR			'$'

#define MAGIC				"$response$"
#define SIZE_TAB			12

// This is 8 x 64 bytes, so in MMX/SSE2 we support up to 9 limbs of MD5
#define HTMP				512

typedef struct
{
	char	**request;
	size_t	h1tmplen;
	size_t	h3tmplen;
	char	h1tmp[HTMP];
	char	h3tmp[HTMP];
} reqinfo_t;

#define SALT_SIZE			sizeof(reqinfo_t)

/*
  digest authentication scheme :
  h1 = md5(user:realm:password)
  h2 = md5(method:digestURI)
  response = h3 = md5(h1:nonce:nonceCount:ClientNonce:qop:h2)
*/

/* request information */
enum e_req {
	R_RESPONSE,
	R_USER,
	R_REALM,
	R_METHOD,
	R_URI,
	R_NONCE,
	R_NONCECOUNT,
	R_CLIENTNONCE,
	R_QOP
};

/* response:user:realm:method:uri:nonce:nonceCount:ClientNonce:qop */
static struct fmt_tests tests[] = {
	{"$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth", "nocode"},
	{"$response$faa6cb7d676e5b7c17fcbf966436aa0c$moi$myrealm$GET$/$af32592775d27b1cd06356b3a0db9ddf$00000001$8e1d49754a25aea7$auth", "kikou"},
	{NULL}
};

/* used by set_key */
static char (*saved_plain)[PLAINTEXT_LENGTH + 1];

#ifdef MMX_COEF

#define LIMBS	9
static unsigned char *saved_key[LIMBS];
static unsigned int *interm_key;
static unsigned int *crypt_key;

#else

static int (*saved_len);
static unsigned char (*crypt_key)[BINARY_SIZE + 1];

#endif

/* Store information about the request ()*/
static reqinfo_t *rinfo = NULL;

static void init(struct fmt_main *self)
{
#ifdef MMX_COEF
	int i;
#endif
#if defined (_OPENMP) && (defined(MD5_SSE_PARA) || !defined(MMX_COEF))
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
#ifdef MMX_COEF
	for (i = 0; i < LIMBS; i++)
		saved_key[i] = mem_calloc_tiny(64 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	interm_key = mem_calloc_tiny(16 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_tiny(16 * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
#else
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_len = mem_calloc_tiny(sizeof(*saved_len) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int nb = 0;
	int i;

	if (strncmp(ciphertext, MAGIC, strlen(MAGIC)) != 0)
		return 0;
	for (i = 0; ciphertext[i] != 0; i++) {
		if (ciphertext[i] == SEPARATOR) {
			nb++;
		}
	}
	if (nb == 10)
		return 1;
	return 0;
}

static void set_salt(void *salt)
{
	rinfo = salt;
}

static void set_key(char *key, int index)
{
	strcpy(saved_plain[index], key);
#ifndef MMX_COEF
	saved_len[index] = -1;
#endif
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int cmp_all(void *binary, int count)
{
#ifdef MMX_COEF
	unsigned int x,y=0;
#ifdef MD5_SSE_PARA
#ifdef _OPENMP
	for(; y < MD5_SSE_PARA * omp_t; y++)
#else
	for(; y < MD5_SSE_PARA; y++)
#endif
#endif
		for(x = 0; x < MMX_COEF; x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+x] )
				return 1;
		}
	return 0;
#else
	int index;

	for (index = 0; index < count; index++)
		if (!(memcmp(binary, crypt_key[index], BINARY_SIZE)))
			return 1;
	return 0;
#endif
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	unsigned int i,x,y;
	x = index&(MMX_COEF-1);
	y = index/MMX_COEF;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+i*MMX_COEF+x] )
			return 0;
	return 1;
#else
	return !(memcmp(binary, crypt_key[index], BINARY_SIZE));
#endif
}

static int cmp_exact(char *source, int count)
{
	return 1;
}


/* convert hash from binary to ascii */

#ifdef MMX_COEF

// This code should be rewritten in intrinsics, reading from
// MMX or SSE2 output buffers and writing to MMX/SSE2 input buffers.
static inline void sse_bin2ascii(unsigned char *conv, unsigned char *src)
{
	unsigned int index;

	for (index = 0; index < NBKEYS; index++) {
		unsigned int i, j = 0;
		for (i = 0; i < BINARY_SIZE; i += 2) {
			unsigned int t;

			t = (src[GETOUTPOS((i + 1), index)] & 0x0f);
			t <<= 12;
			t |= (src[GETOUTPOS((i + 1), index)] & 0xf0);
			t <<= 4;
			t |= (src[GETOUTPOS(i, index)] & 0x0f);
			t <<= 8;
			t |= ((src[GETOUTPOS(i, index)] & 0xf0) >> 4);
			t += 0x06060606;
			t += ((((t >> 4) & 0x01010101) * 0x27) + 0x2a2a2a2a);
			*(unsigned int*)&conv[GETPOS(j, index)] = t;
			j+=4;
		}
	}
}

#endif /* MMX_COEF */

#ifdef __MMX__
static inline void bin2ascii(__m64 *conv, __m64 *src)
{
	unsigned int i = 0;

	while (i != 4) {
		__m64 l;
		__m64 r;
		__m64 t;
		__m64 u;
		__m64 v;

		/* 32 bits to 64 bits */
		t = _mm_set1_pi32(0x0f0f0f0f);

		/* Bit-wise AND the 64-bit values in M1 and M2.  */
		u = _mm_and_si64(_mm_srli_si64(src[(i / 2)], 4), t);
		v = _mm_and_si64(src[(i / 2)], t);

		/* interleaving */
		l = _mm_unpacklo_pi8(u, v);
		r = _mm_unpackhi_pi8(u, v);

		t = _mm_set1_pi32(0x06060606);
		l = _mm_add_pi32(l, t);
		r = _mm_add_pi32(r, t);

		t = _mm_set1_pi32(0x01010101);
		/* u = (l << 4) & t */
		u = _mm_and_si64(_mm_srli_si64(l, 4), t);
		/* v = (r << 4) & t */
		v = _mm_and_si64(_mm_srli_si64(r, 4), t);

		t = _mm_set1_pi32(0x00270027);
		/* Multiply four 16-bit values in M1 by four 16-bit values in M2 and produce
		   the low 16 bits of the results.  */
		u = _mm_mullo_pi16(u, t);
		v = _mm_mullo_pi16(v, t);

		t = _mm_set1_pi32(0x2a2a2a2a);
		u = _mm_add_pi32(u, t);
		v = _mm_add_pi32(v, t);

		conv[(i++)] = _mm_add_pi32(l, u);
		conv[(i++)] = _mm_add_pi32(r, v);
	}
}

#else

static inline void bin2ascii(uint32_t *conv, uint32_t *source)
{
	unsigned char *src = (unsigned char*)source;
	unsigned int i;
	unsigned int j = 0;
	uint32_t t = 0;

	for (i = 0; i < BINARY_SIZE; i += 2) {
#if (ARCH_LITTLE_ENDIAN == 0)
		t = (src[i] & 0xf0);
		t *= 0x10;
		t += (src[i] & 0x0f);
		t *= 0x1000;
		t += (src[(i + 1)] & 0xf0);
		t *= 0x10;
		t += (src[(i + 1)] & 0x0f);
#else
		t = (src[(i + 1)] & 0x0f);
		t *= 0x1000;
		t += (src[(i + 1)] & 0xf0);
		t *= 0x10;
		t += (src[i] & 0x0f);
		t *= 0x100;
		t += ((src[i] & 0xf0) >> 4);
#endif
		t += 0x06060606;
		t += ((((t >> 4) & 0x01010101) * 0x27) + 0x2a2a2a2a);
		conv[(j++)] = t;
	}
}

#endif /* MMX */

#if MMX_COEF
static inline void crypt_done(unsigned const int *source, unsigned int *dest, int index)
{
	unsigned int i;
	unsigned const int *s = &source[(index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*4*MMX_COEF];
	unsigned int *d = &dest[(index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*4*MMX_COEF];

	for (i = 0; i < BINARY_SIZE / 4; i++) {
		*d = *s;
		s += MMX_COEF;
		d += MMX_COEF;
	}
}
#endif

static void crypt_all(int count)
{
#if MMX_COEF
#if defined(_OPENMP) && defined(MD5_SSE_PARA)
#define ti	(thread*NBKEYS+index)
	int thread;
#pragma omp parallel for
	for (thread = 0; thread < (count+NBKEYS-1)/NBKEYS; thread++)
#else
#define thread	0
#define ti	index
#endif
	{
		static unsigned int crypt_len[NBKEYS];
		unsigned int index, i, shortest, longest;

		for (index = 0; index < NBKEYS; index++)
		{
			int len;
			char temp;
			const char *key;

			key = rinfo->h1tmp;
			for (len = 0; len < rinfo->h1tmplen; len += 4, key += 4)
				*(ARCH_WORD_32*)&saved_key[len>>6][GETPOS(len, ti)] = *(ARCH_WORD_32*)key;
			len = rinfo->h1tmplen;
			key = (char*)&saved_plain[ti];
			while((temp = *key++)) {
				saved_key[len>>6][GETPOS(len, ti)] = temp;
				len++;
			}
			saved_key[len>>6][GETPOS(len, ti)] = 0x80;

			// Clean rest of this buffer
			i = len;
			while (++i & 3)
				saved_key[i>>6][GETPOS(i, ti)] = 0;
			for (; i < (((len+8)>>6)+1)*64; i += 4)
				*(ARCH_WORD_32*)&saved_key[i>>6][GETPOS(i, ti)] = 0;

			((unsigned int *)saved_key[(len+8)>>6])[14*MMX_COEF + (ti&3) + (ti>>2)*16*MMX_COEF] = len << 3;
		}

#ifdef MD5_SSE_PARA
		SSEmd5body(&saved_key[0][thread*64*NBKEYS], &crypt_key[thread*4*NBKEYS], 1);
#else
		mdfivemmx_nosizeupdate((unsigned char*)&crypt_key[thread*4*NBKEYS], &saved_key[0][thread*64*NBKEYS], 0);
#endif
		sse_bin2ascii((unsigned char*)&saved_key[0][thread*64*NBKEYS], (unsigned char*)&crypt_key[thread*4*NBKEYS]);

		longest = 0; shortest = HTMP;
		for (index = 0; index < NBKEYS; index++)
		{
			const char *key;
			int i, len;

			len = CIPHERTEXT_LENGTH - 1;
			key = rinfo->h3tmp + CIPHERTEXT_LENGTH;

			// Copy a char at a time until aligned at destination
			while (++len & 3)
				saved_key[len>>6][GETPOS(len, ti)] = *key++;

			// ...then a word at a time. This is a good boost, we are copying over 100 bytes.
			for (;len < rinfo->h3tmplen; len += 4, key += 4)
				*(ARCH_WORD_32*)&saved_key[len>>6][GETPOS(len, ti)] = *(ARCH_WORD_32*)key;
			len = rinfo->h3tmplen;
			saved_key[len>>6][GETPOS(len, ti)] = 0x80;

			// Clean rest of this buffer
			i = len;
			while (++i & 3)
				saved_key[i>>6][GETPOS(i, ti)] = 0;
			//for (; i < (((len+8)>>6)+1)*64; i += 4)
			for (; i <= crypt_len[index]; i += 4)
				*(ARCH_WORD_32*)&saved_key[i>>6][GETPOS(i, ti)] = 0;

			((unsigned int *)saved_key[(len+8)>>6])[14*MMX_COEF + (ti&3) + (ti>>2)*16*MMX_COEF] = len << 3;
			crypt_len[index] = len;
			if (len > longest)
				longest = len;
			if (len < shortest)
				shortest = len;
		}

		// First limb
#ifdef MD5_SSE_PARA
		SSEmd5body(&saved_key[0][thread*64*NBKEYS], &interm_key[thread*4*NBKEYS], 1);
#else
		mdfivemmx_nosizeupdate((unsigned char*)&interm_key[thread*4*NBKEYS], &saved_key[0][thread*64*NBKEYS], 0);
#endif
		// Copy any output that is done now
		if (shortest < 56) {
			if (longest < 56)
				memcpy(&crypt_key[thread*4*NBKEYS], &interm_key[thread*4*NBKEYS], 16*NBKEYS);
			else
				for (index = 0; index < NBKEYS; index++)
					if (crypt_len[index] < 56)
						crypt_done(interm_key, crypt_key, ti);
		}
		// Do the rest of the limbs
		for (i = 1; i < (((longest + 8) >> 6) + 1); i++) {
#ifdef MD5_SSE_PARA
			SSEmd5body(&saved_key[i][thread*64*NBKEYS], &interm_key[thread*4*NBKEYS], 0);
#else
			mdfivemmx_noinit_nosizeupdate((unsigned char*)&interm_key[thread*4*NBKEYS], &saved_key[i][thread*64*NBKEYS], 0);
#endif
			// Copy any output that is done now
			if (shortest < i*64+56) {
				if (shortest > (i-1)*64+55 && longest < i*64+56)
					memcpy(&crypt_key[thread*4*NBKEYS], &interm_key[thread*4*NBKEYS], 16*NBKEYS);
				else
					for (index = 0; index < NBKEYS; index++)
						if (((crypt_len[index] + 8) >> 6) == i)
							crypt_done(interm_key, crypt_key, ti);
			}
		}
	}

#undef thread
#undef ti
#else

	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		MD5_CTX ctx;
		int len;
#ifdef _OPENMP
		char h3tmp[HTMP];
		char h1tmp[HTMP];
#else
		char *h3tmp;
		char *h1tmp;
#endif
		size_t tmp;
#ifdef __MMX__
		__m64 h1[BINARY_SIZE / sizeof(__m64)];
		__m64 conv[CIPHERTEXT_LENGTH / sizeof(__m64) + 1];
#else
		uint32_t h1[BINARY_SIZE / sizeof(uint32_t)];
		uint32_t conv[(CIPHERTEXT_LENGTH / sizeof(uint32_t)) + 1];
#endif

		tmp = rinfo->h1tmplen;
		if ((len = saved_len[index]) < 0)
			len = saved_len[index] = strlen(saved_plain[index]);
#ifdef _OPENMP
		memcpy(h1tmp, rinfo->h1tmp, tmp);
		memcpy(h3tmp + CIPHERTEXT_LENGTH, rinfo->h3tmp + CIPHERTEXT_LENGTH, rinfo->h3tmplen - CIPHERTEXT_LENGTH);
#else
		h3tmp = rinfo->h3tmp;
		h1tmp = rinfo->h1tmp;
#endif
		memcpy(&h1tmp[tmp], saved_plain[index], len);

		MD5_Init(&ctx);
		MD5_Update(&ctx, h1tmp, len + tmp);
		MD5_Final((unsigned char*)h1, &ctx);
		bin2ascii(conv, h1);

		memcpy(h3tmp, conv, CIPHERTEXT_LENGTH);

		MD5_Init(&ctx);
		MD5_Update(&ctx, h3tmp, rinfo->h3tmplen);
		MD5_Final(crypt_key[index], &ctx);
	}
#endif
}

static char *mystrndup(const char *s, size_t n)
{
	size_t tmp;
	size_t size;
	char *ret;

	for (tmp = 0; s[tmp] != 0 && tmp <= n; tmp++);
	size = n;
	if (tmp < size)
		size = tmp;
	if ((ret = mem_alloc_tiny(sizeof(char) * size + 1, MEM_ALIGN_WORD)) == NULL)
		return NULL;
	memmove(ret, s, size);
	ret[size] = 0;
	return ret;
}

static size_t reqlen(char *str)
{
	size_t len;

	for (len = 0; str[len] != 0 && str[len] != SEPARATOR; len++);
	return len;
}

static void *salt(char *ciphertext)
{
	int nb;
	int i;
	char **request;
	char *str;
	reqinfo_t *r;
#ifdef __MMX__
	__m64 h2[BINARY_SIZE / sizeof(__m64)];
	__m64 conv[CIPHERTEXT_LENGTH / sizeof(__m64) + 1];
#else
	unsigned int h2[BINARY_SIZE / sizeof(unsigned int)];
	uint32_t conv[(CIPHERTEXT_LENGTH / sizeof(uint32_t)) + 1];
#endif
	MD5_CTX ctx;

	/* parse the password string */
	request = mem_alloc_tiny(sizeof(char*) * SIZE_TAB, MEM_ALIGN_WORD);
	r = mem_calloc_tiny(sizeof(*r), MEM_ALIGN_WORD);
	for (nb = 0, i = 1; ciphertext[i] != 0; i++) {
		if (ciphertext[i] == SEPARATOR) {
			i++;
			request[nb] = mystrndup(&ciphertext[i], reqlen(&ciphertext[i]));
			nb++;
		}
	}

	/* calculate h2 (h2 = md5(method:digestURI))*/
	str = mem_alloc(strlen(request[R_METHOD]) + strlen(request[R_URI]) + 2);
	sprintf(str, "%s:%s", request[R_METHOD], request[R_URI]);
	MD5_Init(&ctx);
	MD5_Update(&ctx, str, strlen(str));
	MD5_Final((unsigned char*)h2, &ctx);

	memset(conv, 0, CIPHERTEXT_LENGTH + 1);
	bin2ascii(conv, h2);
	MEM_FREE(str);

	/* create a part of h1 (h1tmp = request:realm:)*/
	snprintf(r->h1tmp, HTMP - PLAINTEXT_LENGTH, "%s:%s:", request[R_USER], request[R_REALM]);

	/* create a part of h3 (h3tmp = nonce:noncecount:clientnonce:qop:h2)*/
	snprintf(&r->h3tmp[CIPHERTEXT_LENGTH], HTMP - CIPHERTEXT_LENGTH, ":%s:%s:%s:%s:%s",
	         request[R_NONCE], request[R_NONCECOUNT], request[R_CLIENTNONCE],
	         request[R_QOP], (char*)conv);

	r->request = request;
	r->h1tmplen = strlen(r->h1tmp);
	r->h3tmplen = strlen(&r->h3tmp[CIPHERTEXT_LENGTH]) + CIPHERTEXT_LENGTH;

	return r;
}

/* convert response to binary form */
static void *binary(char *ciphertext)
{
	static unsigned int realcipher[BINARY_SIZE / sizeof(int)];
	int i;

	ciphertext += 10;
	for (i = 0; i < BINARY_SIZE; i++) {
		((unsigned char*)realcipher)[i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
	return (void*) realcipher;
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

#ifdef MMX_COEF
#define HASH_OFFSET (index&(MMX_COEF-1))+(index/MMX_COEF)*MMX_COEF*4
static int get_hash_0(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return *(ARCH_WORD_32*)&crypt_key[index] & 0xf; }
static int get_hash_1(int index) { return *(ARCH_WORD_32*)&crypt_key[index] & 0xff; }
static int get_hash_2(int index) { return *(ARCH_WORD_32*)&crypt_key[index] & 0xfff; }
static int get_hash_3(int index) { return *(ARCH_WORD_32*)&crypt_key[index] & 0xffff; }
static int get_hash_4(int index) { return *(ARCH_WORD_32*)&crypt_key[index] & 0xfffff; }
static int get_hash_5(int index) { return *(ARCH_WORD_32*)&crypt_key[index] & 0xffffff; }
static int get_hash_6(int index) { return *(ARCH_WORD_32*)&crypt_key[index] & 0x7ffffff; }
#endif

struct fmt_main fmt_HDAA = {
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
#if !defined(MMX_COEF) || defined(MD5_SSE_PARA)
		FMT_OMP |
#endif
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
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		fmt_default_salt_hash,
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
