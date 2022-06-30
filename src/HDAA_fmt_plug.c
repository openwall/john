/*
 * HTTP Digest access authentication patch for John the Ripper.
 *
 * Written by Romain Raboin. OMP and intrinsics support by magnum.
 *
 * This software is Copyright (c) 2008 Romain Raboin - romain.raboin at
 * gmail.com, and Copyright (c) 2012 magnum and it is hereby released to
 * the general public under the following terms:  Redistribution and
 * use in source and binary forms, with or without modification, are
 * permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_HDAA;
#elif FMT_REGISTERS_H
john_register_one(&fmt_HDAA);
#else

#include <stdint.h>
#include <string.h>

#ifdef __MMX__
#include <mmintrin.h>
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "johnswap.h"

#include "simd-intrinsics.h"
#define ALGORITHM_NAME          "MD5 " MD5_ALGORITHM_NAME

#define FORMAT_LABEL            "hdaa"
#define FORMAT_NAME             "HTTP Digest access authentication"
#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        7
#define PLAINTEXT_LENGTH        32
#define CIPHERTEXT_LENGTH       32
#define BINARY_SIZE             16
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(reqinfo_t)
#define SALT_ALIGN              sizeof(size_t)

#ifdef SIMD_COEF_32
#define NBKEYS                  (SIMD_COEF_32 * SIMD_PARA_MD5)
#define MIN_KEYS_PER_CRYPT      NBKEYS
#define MAX_KEYS_PER_CRYPT      NBKEYS
#if ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&60)*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#define GETOUTPOS(i, index)     ( (index&(SIMD_COEF_32-1))*4 + ((i)&0x1c)*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32 )
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&60)*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#define GETOUTPOS(i, index)     ( (index&(SIMD_COEF_32-1))*4 + ((i)&0x1c)*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32 )
#endif
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#endif

#define SEPARATOR               '$'
#define FORMAT_TAG              "$response$"
#define TAG_LENGTH              (sizeof(FORMAT_TAG)-1)
#define SIZE_TAB                12

// This is 8 x 64 bytes, so in MMX/SSE2 we support up to 9 limbs of MD5
#define HTMP                    512

// That's arbitrary because uri part is not limited by anything natural.
#define MAX_CIPHERTEXT_LEN      8192

typedef struct
{
	size_t h1tmplen;
	size_t h3tmplen;
	char h1tmp[HTMP];
	char h3tmp[HTMP];
} reqinfo_t;

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
	{"$response$56940f87f1f53ade8b7d3c5a102c2bf3$usrx$teN__chars$GET$/4TLHS1TMN9cfsbqSUAdTG3CRq7qtXMptnYfn7mIIi3HRKOMhOks56e$2c0366dcbc$00000001$0153$auth", "passWOrd"},
	{"$response$8663faf2337dbcb2c52882807592ec2c$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$", "pass"},
	{"$response$8663faf2337dbcb2c52882807592ec2c$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a", "pass"},
	/* Apache httpd-2.4.29-1.fc27.x86_64 + Firefox 58.x */
	{"$response$b9b9cb1fcce017ec497b31cc33a572b0$lulu$hyperion$GET$/$IERozb5mBQA=de6a5916efca4c24959b5be7e4ed3fc0c7f1f765$00000006$1bd5678ca084bc0d$auth", "openwall"},
	{"$response$abe32fa35969fd6d77bad0ce3dbfdd3a$lulu$hyperion$GET$/icons/poweredby.png$XkZ1Dr9mBQA=6258d402c7c95b352bab0ba774d6974506e3318b$00000003$bd29e3b874427c73$auth", "openwall"},
	{NULL}
};

/* used by set_key */
static char (*saved_plain)[PLAINTEXT_LENGTH + 1];

#ifdef SIMD_COEF_32

#define LIMBS	9
static unsigned char *saved_key[LIMBS];
static unsigned int *interm_key;
static unsigned int *crypt_key;

#else

static int (*saved_len);
static unsigned char (*crypt_key)[BINARY_SIZE];

#endif

/* Store information about the request ()*/
static reqinfo_t *rinfo = NULL;

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_32
	int i;
#endif
#ifdef SIMD_COEF_32
	for (i = 0; i < LIMBS; i++)
		saved_key[i] = mem_calloc_align(self->params.max_keys_per_crypt,
		                                64, MEM_ALIGN_SIMD);
	interm_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                              16, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                             16, MEM_ALIGN_SIMD);
#else
	saved_len = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_len));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
}

static void done(void)
{
#ifdef SIMD_COEF_32
	int i;
#endif
	MEM_FREE(saved_plain);
	MEM_FREE(crypt_key);
#ifdef SIMD_COEF_32
	MEM_FREE(interm_key);
	for (i = 0; i < LIMBS; i++)
		MEM_FREE(saved_key[i]);
#else
	MEM_FREE(saved_len);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr, *p;
	size_t user_len, realm_len, nonce_len, noncecount_len, clientnonce_len, qop_len;

	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH) != 0)
		return 0;
	if (strlen(ciphertext) > MAX_CIPHERTEXT_LEN)
		return 0;
	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += TAG_LENGTH;

	if ((p = strtokm(ctcopy, "$")) == NULL) /* hash */
		goto err;
	if (!ishexlc(p) || strlen(p) != 32)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* user */
		goto err;
	user_len = strlen(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* realm */
		goto err;
	realm_len = strlen(p);
	/* snprintf() later would truncate data making hash uncrackable. */
	if (user_len + realm_len + 2 > HTMP - PLAINTEXT_LENGTH - 1)
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* method */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* uri */
		goto err;
	if ((p = strtokm(NULL, "$")) == NULL) /* nonce */
		goto err;
	nonce_len = strlen(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* End of legacy HDAA or noncecount */
		goto end_hdaa_legacy;
	noncecount_len = strlen(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* clientnonce */
		goto err;
	clientnonce_len = strlen(p);
	if ((p = strtokm(NULL, "$")) == NULL) /* qop */
		goto err;
	qop_len = strlen(p);
	if ((p = strtokm(NULL, "$")) != NULL)
		goto err;
	if (nonce_len + noncecount_len + clientnonce_len + qop_len + 32 + 5 > HTMP - CIPHERTEXT_LENGTH - 1)
		goto err;

end_hdaa_legacy:
	MEM_FREE(keeptr);
	if (nonce_len + 32 + 2 > HTMP - CIPHERTEXT_LENGTH - 1)
		return 0;
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

// Normalize shorter hashes, to allow with or without trailing '$' character.
static char *split(char *ciphertext, int index, struct fmt_main *self)
{
	char *cp;
	if (strncmp(ciphertext, FORMAT_TAG, TAG_LENGTH))
		return ciphertext;
	if (strlen(ciphertext) > MAX_CIPHERTEXT_LEN)
		return ciphertext;
	cp = ciphertext + TAG_LENGTH;
	cp = strchr(cp, '$'); if (!cp) return ciphertext;
	cp = strchr(cp+1, '$'); if (!cp) return ciphertext;
	cp = strchr(cp+1, '$'); if (!cp) return ciphertext;
	cp = strchr(cp+1, '$'); if (!cp) return ciphertext;
	cp = strchr(cp+1, '$'); if (!cp) return ciphertext;
	// now if we have $binary_hash$ then we remove the last '$' char
	if (strlen(cp) == 1 + BINARY_SIZE*2 + 1) {
		static char *out;
		if (!out)
			out = mem_alloc_tiny(MAX_CIPHERTEXT_LEN + 1, MEM_ALIGN_NONE);
		strnzcpy(out, ciphertext, MAX_CIPHERTEXT_LEN + 1);
		out[strlen(out)-1] = 0;
		return out;
	}
	return ciphertext;
}

static void set_salt(void *salt)
{
	rinfo = salt;
}

static void set_key(char *key, int index)
{
	strcpy(saved_plain[index], key);
#ifndef SIMD_COEF_32
	saved_len[index] = -1;
#endif
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int cmp_all(void *binary, int count)
{
#ifdef SIMD_COEF_32
	unsigned int x, y;
	for (y = 0; y < SIMD_PARA_MD5; y++)
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[y*SIMD_COEF_32*4+x] )
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
#ifdef SIMD_COEF_32
	unsigned int i,x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	for (i=0;i<(BINARY_SIZE/4);i++)
		if ( ((uint32_t*)binary)[i] != ((uint32_t*)crypt_key)[y*SIMD_COEF_32*4+i*SIMD_COEF_32+x] )
			return 0;
	return 1;
#else
	return !(memcmp(binary, crypt_key[index], BINARY_SIZE));
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}


/* convert hash from binary to ascii */

#ifdef SIMD_COEF_32

// This code should be rewritten in intrinsics, reading from
// MMX or SSE2 output buffers and writing to MMX/SSE2 input buffers.
inline static void sse_bin2ascii(unsigned char *conv, unsigned char *src)
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
#if ARCH_LITTLE_ENDIAN
			*(unsigned int*)&conv[GETPOS(j, index)] = t;
#else
			*(unsigned int*)&conv[GETPOS((j+3), index)] = t;
#endif
			j+=4;
		}
	}
}

#endif /* SIMD_COEF_32 */

#ifdef __MMX__
inline static void bin2ascii(__m64 *conv, __m64 *src)
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
	__asm__ __volatile__("emms");
}

#else

inline static void bin2ascii(uint32_t *conv, uint32_t *source)
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

#if SIMD_COEF_32
inline static void crypt_done(unsigned const int *source, unsigned int *dest, int index)
{
	unsigned int i;
	unsigned const int *s = &source[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*4*SIMD_COEF_32];
	unsigned int *d = &dest[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*4*SIMD_COEF_32];

	for (i = 0; i < BINARY_SIZE / 4; i++) {
		*d = *s;
		s += SIMD_COEF_32;
		d += SIMD_COEF_32;
	}
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#if SIMD_COEF_32
#define thread	0
#define ti	index
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
#if ARCH_LITTLE_ENDIAN
				*(uint32_t*)&saved_key[len>>6][GETPOS(len, ti)] = *(uint32_t*)key;
#else
				*(uint32_t*)&saved_key[len>>6][GETPOS(len+3, ti)] = JOHNSWAP(*(uint32_t*)key);
#endif
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
#if ARCH_LITTLE_ENDIAN
				*(uint32_t*)&saved_key[i>>6][GETPOS(i, ti)] = 0;
#else
				*(uint32_t*)&saved_key[i>>6][GETPOS(i+3, ti)] = 0;
#endif

			((unsigned int *)saved_key[(len+8)>>6])[14*SIMD_COEF_32 + (ti&(SIMD_COEF_32-1)) + (ti/SIMD_COEF_32)*16*SIMD_COEF_32] = len << 3;
		}

		SIMDmd5body(&saved_key[0][thread*64*NBKEYS], &crypt_key[thread*4*NBKEYS], NULL, SSEi_MIXED_IN);
		sse_bin2ascii((unsigned char*)&saved_key[0][thread*64*NBKEYS], (unsigned char*)&crypt_key[thread*4*NBKEYS]);

		longest = 0; shortest = HTMP;
		for (index = 0; index < NBKEYS; index++)
		{
			const char *key;
			int i, len;

			len = CIPHERTEXT_LENGTH - 1;
			key = rinfo->h3tmp + CIPHERTEXT_LENGTH;

#if !ARCH_ALLOWS_UNALIGNED
			if (len != 3) {
				while (++len < rinfo->h3tmplen )
					saved_key[len>>6][GETPOS(len, ti)] = *key++;
			} else
#endif
			{
			// Copy a char at a time until aligned at destination
			while (++len & 3)
				saved_key[len>>6][GETPOS(len, ti)] = *key++;
			// ...then a word at a time. This is a good boost, we are copying over 100 bytes.
			for (;len < rinfo->h3tmplen; len += 4, key += 4) {
#if ARCH_LITTLE_ENDIAN
				*(uint32_t*)&saved_key[len>>6][GETPOS(len, ti)] = *(uint32_t*)key;
#else
				*(uint32_t*)&saved_key[len>>6][GETPOS(len+3, ti)] = *(uint32_t*)key;
#endif
			}
			}

			len = rinfo->h3tmplen;
			saved_key[len>>6][GETPOS(len, ti)] = 0x80;

			// Clean rest of this buffer
			i = len;
			while (++i & 3)
				saved_key[i>>6][GETPOS(i, ti)] = 0;
			//for (; i < (((len+8)>>6)+1)*64; i += 4)
			for (; i <= crypt_len[index]; i += 4)
#if ARCH_LITTLE_ENDIAN
				*(uint32_t*)&saved_key[i>>6][GETPOS(i, ti)] = 0;
#else
				*(uint32_t*)&saved_key[i>>6][GETPOS(i+3, ti)] = 0;
#endif

			((unsigned int *)saved_key[(len+8)>>6])[14*SIMD_COEF_32 + (ti&(SIMD_COEF_32-1)) + (ti/SIMD_COEF_32)*16*SIMD_COEF_32] = len << 3;
			crypt_len[index] = len;
			if (len > longest)
				longest = len;
			if (len < shortest)
				shortest = len;
		}

		// First limb
		SIMDmd5body(&saved_key[0][thread*64*NBKEYS], &interm_key[thread*4*NBKEYS], NULL, SSEi_MIXED_IN);
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
			SIMDmd5body(&saved_key[i][thread*64*NBKEYS], &interm_key[thread*4*NBKEYS], &interm_key[thread*4*NBKEYS], SSEi_RELOAD|SSEi_MIXED_IN);
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
	int index;
	for (index = 0; index < count; index++) {
		MD5_CTX ctx;
		int len;
		char *h3tmp;
		char *h1tmp;
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
		h3tmp = rinfo->h3tmp;
		h1tmp = rinfo->h1tmp;
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
	return count;
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
	if ((ret = mem_alloc(sizeof(char) * size + 1)) == NULL)
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

static void *get_salt(char *ciphertext)
{
	int nb;
	int i;
	char *request[SIZE_TAB];
	char *str;
	static reqinfo_t *r;
#ifdef __MMX__
	__m64 h2[BINARY_SIZE / sizeof(__m64)];
	__m64 conv[CIPHERTEXT_LENGTH / sizeof(__m64) + 1];
#else
	unsigned int h2[BINARY_SIZE / sizeof(unsigned int)];
	uint32_t conv[(CIPHERTEXT_LENGTH / sizeof(uint32_t)) + 1];
#endif
	MD5_CTX ctx;

	/* parse the password string */
	if (!r) r = mem_alloc_tiny(sizeof(*r), SALT_ALIGN);
	memset(r, 0, sizeof(*r));
	for (nb = 0, i = 1; ciphertext[i] != 0; i++) {
		if (ciphertext[i] == SEPARATOR) {
			i++;
			request[nb] = mystrndup(&ciphertext[i], reqlen(&ciphertext[i]));
			nb++;
			if (!ciphertext[i])
				break;
		}
	}
	while (nb < SIZE_TAB) {
		request[nb++] = NULL;
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
	if (request[R_CLIENTNONCE] == NULL)
		snprintf(&r->h3tmp[CIPHERTEXT_LENGTH], HTMP - CIPHERTEXT_LENGTH, ":%s:%s",
		         request[R_NONCE], (char*)conv);
	else
		snprintf(&r->h3tmp[CIPHERTEXT_LENGTH], HTMP - CIPHERTEXT_LENGTH, ":%s:%s:%s:%s:%s",
		         request[R_NONCE], request[R_NONCECOUNT], request[R_CLIENTNONCE],
		         request[R_QOP], (char*)conv);

	r->h1tmplen = strlen(r->h1tmp);
	r->h3tmplen = strlen(&r->h3tmp[CIPHERTEXT_LENGTH]) + CIPHERTEXT_LENGTH;

	for (nb=0; nb < SIZE_TAB; ++nb) {
		MEM_FREE(request[nb]);
	}
	return r;
}

/* convert response to binary form */
static void *get_binary(char *ciphertext)
{
	static unsigned int realcipher[BINARY_SIZE / sizeof(int)];
	int i;

	ciphertext += TAG_LENGTH;
	for (i = 0; i < BINARY_SIZE; i++) {
		((unsigned char*)realcipher)[i] = atoi16[ARCH_INDEX(ciphertext[i * 2])] * 16 +
			atoi16[ARCH_INDEX(ciphertext[i * 2 + 1])];
	}
#if !ARCH_LITTLE_ENDIAN && defined(SIMD_COEF_32)
	alter_endianity(realcipher, 16);
#endif
	return (void*) realcipher;
}

#define COMMON_GET_HASH_SIMD32 4
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

struct fmt_main fmt_HDAA = {
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
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ FORMAT_TAG },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
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
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
