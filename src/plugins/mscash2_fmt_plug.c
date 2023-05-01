/* MSCASH2 patch for John the Ripper written by S3nf in 2010, 2011
 * a slow but working version
 *
 * Cracking Domain Cached Credentials for modern Windows operating systems, supporting:
 *     - Windows Vista
 *     - Windows 7
 *     - Windows Server 2008
 *
 * This software was written by S3nf in 2010, 2011. No copyright is claimed, and the software is hereby placed in
 * the public domain. In case this attempt to disclaim copyright and place the software in the public domain
 * is deemed null and void, then the software is Copyright (c) 2010, 2011 S3nf and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Modified for optional utf-8 support by magnum 2011, same terms as above
 *
 * Code redone/optimized by JimF June 2011.  (2x to 10x improvement in speed)
 *	- Code converted to oSSL (for non-sse builds).  The inline MD4/SHA1 replaced.  This reduced
 *	  about 900 lines down to 60 or so, which were much easier to follow.  This was a preliminary
 *	  step to getting SSE2 added.  Once done, this ended up faster than the original, so the new
 *	  simplified code was kept.
 *	- Setup of ipad/opad only done once per PW/Salt  about 10-15% speedup
 *	- 1/2 of the encryption performed within inner loop was moved outside of inner loop (nearly doubles speed)
 *	- changed signature from M$salt#hash to $DCC2$iterations#salt#hash
 *	- variable iterations now 'possible'.  Default is 10240
 *	- increased salt (user name) upto 22 UC2 characters. Bug in original code only allowed up to 8 chars.
 *	- Added SSE2(/MMX) and SSE2i to the deep inner loop.  2x to 4x speedup.
 *	- total about 2x to 10x improvment in speed (depending upon CPU and compiler).  Some compilers
 *	  were more efficient with original code, and thus received less of a performance boost.  Others
 *	  got a signicant improvment.
 *	- The utf8 code was greatly simplified.  There was no reason to try to optimized the UTF code as
 *	  the format is so slow that utf8 conversion is a non-issue. Thus we always call the enc_to_utf16()
 *	  at the proper locations, and let that function deal with being in --encoding=utf8 switch mode or not.
 *	- Fixed code to properly work with BE systems, and alignment required systems.
 *	- Made some 'interface' changes to the SSE2i for SHA1, and to the sha-mmx.S code, to make it work
 *	  properly, and to make it more efficient.  We deal with 2 SHA1 states, and alternate back and forth
 *	  between them. The changes to the SSE2i code, were to optimize this dual state, and the changes
 *	  to the .S code were simply to make it work at all and the same optimizations were placed there.
 *	- the OMP code was removed during initial re-write, and was properly re-incorporated by magnum.
 *
 *  In June 2013, salt length (Username) increased from 22 to 128, and max password length increased
 *     from 27 to 125 bytes (unicode bytes, so 250 ?)
 *
 * This module is based on:
 *     - the MSCASH patch for john written by Alain Espinosa <alainesp at gmail.com> in 2007
 *     - RFC 1320 - The MD4 Message-Digest Algorithm
 *     - RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *     - RFC 3174 - US Secure Hash Algorithm 1 (SHA1)
 *     - the HMAC-SHA1 implementation of the PolarSSL open source cryptographic library (http://polarssl.org/)
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_mscash2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_mscash2);
#else

#include <string.h>

#if defined (_OPENMP)
#include <omp.h>
#endif

#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"
#include "options.h"
#include "sha.h"
#include "md4.h"
#include "simd-intrinsics.h"
#include "loader.h"
#include "mscash_common.h"

#ifndef OMP_SCALE
#define OMP_SCALE			2 // Tuned on core i7 w/ MKPC
#endif

#define ITERATIONS			10240
static unsigned iteration_cnt =	(ITERATIONS); /* this will get changed at runtime, salt loading */

#define FORMAT_LABEL			"mscash2"
#define FORMAT_NAME			"MS Cache Hash 2 (DCC2)"

#define MAX_SALT_LEN            128
#define PLAINTEXT_LENGTH        125

#define SALT_SIZE			(MAX_SALT_LEN*2+4)

#define ALGORITHM_NAME			"PBKDF2-SHA1 " SHA1_ALGORITHM_NAME

#ifdef SIMD_COEF_32
#define MS_NUM_KEYS			(SIMD_COEF_32*SIMD_PARA_SHA1)
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)	( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#else
#define GETPOS(i, index)	( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32*4 )
#endif
static unsigned char (*sse_hash1);
static unsigned char (*sse_crypt1);
static unsigned char (*sse_crypt2);

#else
 #define MS_NUM_KEYS			1
#endif

#define MIN_KEYS_PER_CRYPT		MS_NUM_KEYS
#define MAX_KEYS_PER_CRYPT		(MS_NUM_KEYS * 2)

#define HASH_LEN			(16+48)

static unsigned char *salt_buffer;
static unsigned int   salt_len;
static unsigned char(*key);
static unsigned int   new_key = 1;
static unsigned char(*md4hash); // allows the md4 of user, and salt to be appended to it.  the md4 is ntlm, with the salt is DCC1
static unsigned int (*crypt_out);

static void init(struct fmt_main *self)
{

	omp_autotune(self, OMP_SCALE);

	key = mem_calloc(self->params.max_keys_per_crypt,
	                 (PLAINTEXT_LENGTH + 1));
	md4hash = mem_calloc(self->params.max_keys_per_crypt,
	                     HASH_LEN);
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       BINARY_SIZE);
#if defined (SIMD_COEF_32)
	sse_hash1 = mem_calloc_align(self->params.max_keys_per_crypt,
	                             sizeof(*sse_hash1)*SHA_BUF_SIZ*4,
	                             MEM_ALIGN_SIMD);
	sse_crypt1 = mem_calloc_align(self->params.max_keys_per_crypt,
	                              sizeof(*sse_crypt1) * 20, MEM_ALIGN_SIMD);
	sse_crypt2 = mem_calloc_align(self->params.max_keys_per_crypt,
	                              sizeof(*sse_crypt2) * 20, MEM_ALIGN_SIMD);
	{
		int index;
		for (index = 0; index < self->params.max_keys_per_crypt; ++index) {
			// set the length of all hash1 SSE buffer to 64+20 * 8 bits
			// The 64 is for the ipad/opad, the 20 is for the length of the SHA1 buffer that also gets into each crypt
			// this works for SSEi
			((unsigned int *)sse_hash1)[15*SIMD_COEF_32 + (index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = (84<<3); // all encrypts are 64+20 bytes.
			sse_hash1[GETPOS(20,index)] = 0x80;
		}
	}
	// From this point on, we ONLY touch the first 20 bytes (* SIMD_COEF_32) of each buffer 'block'.  If !SHA_PARA', then only the first
	// block is written to after this, if there are more that one SHA_PARA, then the start of each para block will be updated inside the inner loop.
#endif

	mscash2_adjust_tests(options.target_enc, PLAINTEXT_LENGTH, MAX_SALT_LEN);
}

static void done(void)
{
#ifdef SIMD_COEF_32
	MEM_FREE(sse_crypt2);
	MEM_FREE(sse_crypt1);
	MEM_FREE(sse_hash1);
#endif
	MEM_FREE(crypt_out);
	MEM_FREE(md4hash);
	MEM_FREE(key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return mscash2_common_valid(ciphertext, MAX_SALT_LEN, self);
}

static void set_salt(void *salt) {
	UTF16 *p = (UTF16*)salt;
	salt_len = *p++;
	iteration_cnt = *p++;
	salt_buffer = (unsigned char*)p;
}

static void *get_salt(char *ciphertext)
{
	static UTF16 out[130+1];
	unsigned char input[MAX_SALT_LEN*3+1];
	int i, iterations, utf16len;
	char *lasth = strrchr(ciphertext, '#');

	memset(out, 0, sizeof(out));

	sscanf(&ciphertext[6], "%d", &iterations);
	ciphertext = strchr(ciphertext, '#') + 1;

	for (i = 0; &ciphertext[i] < lasth; i++)
		input[i] = (unsigned char)ciphertext[i];
	input[i] = 0;

	utf16len = enc_to_utf16(&out[2], MAX_SALT_LEN, input, i);
	if (utf16len < 0)
		utf16len = strlen16(&out[2]);
	out[0] = utf16len << 1;
	out[1] = iterations;
	return out;
}

static void *get_binary(char *ciphertext)
{
	static unsigned int out[BINARY_SIZE / sizeof(unsigned int)];
	unsigned int i;
	unsigned int temp;

	/* We need to allow salt containing '#' so we search backwards */
	ciphertext = strrchr(ciphertext, '#') + 1;

	for (i = 0; i < 4 ;i++)
	{
#if ARCH_LITTLE_ENDIAN
		temp  = ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 0])])) << 4;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 1])]));
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 2])])) << 12;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 3])])) << 8;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 4])])) << 20;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 5])])) << 16;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 6])])) << 28;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 7])])) << 24;
#else
		temp  = ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 6])])) << 4;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 7])]));
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 4])])) << 12;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 5])])) << 8;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 2])])) << 20;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 3])])) << 16;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 0])])) << 28;
		temp |= ((unsigned int)(atoi16[ARCH_INDEX(ciphertext[i * 8 + 1])])) << 24;
#endif
		out[i] = temp;
	}
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN==1
	alter_endianity(out, BINARY_SIZE);
#endif
	return out;
}


static int binary_hash_0(void *binary)
{
	return ((unsigned int*)binary)[3] & PH_MASK_0;
}


static int binary_hash_1(void *binary)
{
	return ((unsigned int*)binary)[3] & PH_MASK_1;
}


static int binary_hash_2(void *binary)
{
	return ((unsigned int*)binary)[3] & PH_MASK_2;
}


static int binary_hash_3(void *binary)
{
	return ((unsigned int*)binary)[3] & PH_MASK_3;
}


static int binary_hash_4(void *binary)
{
	return ((unsigned int*)binary)[3] & PH_MASK_4;
}

static int binary_hash_5(void *binary)
{
	return ((unsigned int*)binary)[3] & PH_MASK_5;
}

static int binary_hash_6(void *binary)
{
	return ((unsigned int*)binary)[3] & PH_MASK_6;
}

static int get_hash_0(int index)
{
	return crypt_out[4 * index + 3] & PH_MASK_0;
}

static int get_hash_1(int index)
{
	return crypt_out[4 * index + 3] & PH_MASK_1;
}

static int get_hash_2(int index)
{
	return crypt_out[4 * index + 3] & PH_MASK_2;
}

static int get_hash_3(int index)
{
	return crypt_out[4 * index + 3] & PH_MASK_3;
}

static int get_hash_4(int index)
{
	return crypt_out[4 * index + 3] & PH_MASK_4;
}

static int get_hash_5(int index)
{
	return crypt_out[4 * index + 3] & PH_MASK_5;
}

static int get_hash_6(int index)
{
	return crypt_out[4 * index + 3] & PH_MASK_6;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i = 0;
	unsigned int d = ((unsigned int *)binary)[3];

	for (; i < count; i++)
		if (d == crypt_out[i * 4 + 3])
			return 1;

	return 0;
}


static int cmp_one(void * binary, int index)
{
	unsigned int *t = (unsigned int *)binary;
	unsigned int a = crypt_out[4 * index + 0];
	unsigned int b = crypt_out[4 * index + 1];
	unsigned int c = crypt_out[4 * index + 2];
	unsigned int d = crypt_out[4 * index + 3];

	if (d != t[3])
		return 0;

	if (c != t[2])
		return 0;

	if (b != t[1])
		return 0;

	return (a == t[0]);
}


static int cmp_exact(char *source, int index)
{
	return 1;
}


static void set_key(char *_key, int index)
{
	strnzcpy ((char*)&key[index*(PLAINTEXT_LENGTH + 1)], _key, (PLAINTEXT_LENGTH + 1));
	new_key = 1;
}


static char *get_key(int index)
{
	return (char*)&key[index*(PLAINTEXT_LENGTH + 1)];
}


// Public domain hash function by DJ Bernstein (salt is a username)
static int salt_hash(void *salt)
{
	UTF16 *n = salt, i;
	unsigned char *s  = (unsigned char*)n;
	unsigned int hash = 5381;
	for (i = 0; i < (*n+2); ++i)
		hash = ((hash<<5)+hash) ^ s[i];
	return hash & (SALT_HASH_SIZE - 1);
}


#ifdef SIMD_COEF_32
// NOTE, in the end, this block will move above the pbkdf2() function, and the #else and #endif wrapping that function will be
// uncommented. Thus, if built for SSE2 (mmx, or intrisic), we get this function. Otherwise we get the pbkdf2() function which
// uses OpenSSL.  However to get the 'layout' right, The code here will walk through the array buffer, calling the pbkdf2
// function.
static void pbkdf2_sse2(int t)
{
	// Thread safe, t is our thread number.
	// All indexes into buffers are offset by (t * MS_NUM_KEYS * (size))
	SHA_CTX ctx1, ctx2;
	unsigned int ipad[SHA_LBLOCK], opad[SHA_LBLOCK];
	unsigned int tmp_hash[SHA_DIGEST_LENGTH/4];
	unsigned int i, j, k, *i1, *i2, *o1, *t_crypt;
	unsigned char *t_sse_crypt1, *t_sse_crypt2, *t_sse_hash1;

	memset(&ipad[4], 0x36, SHA_CBLOCK-16);
	memset(&opad[4], 0x5C, SHA_CBLOCK-16);


	// All pointers get their offset for this thread here. No further offsetting below.
	t_crypt = &crypt_out[t * MS_NUM_KEYS * 4];
	t_sse_crypt1 = &sse_crypt1[t * MS_NUM_KEYS * 20];
	t_sse_crypt2 = &sse_crypt2[t * MS_NUM_KEYS * 20];
	t_sse_hash1 = &sse_hash1[t * MS_NUM_KEYS * SHA_BUF_SIZ * 4];
	i1 = (unsigned int*)t_sse_crypt1;
	i2 = (unsigned int*)t_sse_crypt2;
	o1 = (unsigned int*)t_sse_hash1;

	for (k = 0; k < MS_NUM_KEYS; ++k)
	{
		for (i = 0;i < 4;i++) {
			ipad[i] = t_crypt[k*4+i]^0x36363636;
			opad[i] = t_crypt[k*4+i]^0x5C5C5C5C;
		}

		SHA1_Init(&ctx1);
		SHA1_Init(&ctx2);

		SHA1_Update(&ctx1,ipad,SHA_CBLOCK);
		SHA1_Update(&ctx2,opad,SHA_CBLOCK);

		// we memcopy from flat into SIMD_COEF_32 output buffer's (our 'temp' ctx buffer).
		// This data will NOT need to be BE swapped (it already IS BE swapped).
		i1[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))]               = ctx1.SHA_H0;
		i1[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+SIMD_COEF_32]      = ctx1.SHA_H1;
		i1[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+(SIMD_COEF_32<<1)] = ctx1.SHA_H2;
		i1[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+SIMD_COEF_32*3]    = ctx1.SHA_H3;
		i1[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+(SIMD_COEF_32<<2)] = ctx1.SHA_H4;

		i2[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))]               = ctx2.SHA_H0;
		i2[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+SIMD_COEF_32]      = ctx2.SHA_H1;
		i2[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+(SIMD_COEF_32<<1)] = ctx2.SHA_H2;
		i2[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+SIMD_COEF_32*3]    = ctx2.SHA_H3;
		i2[(k/SIMD_COEF_32)*SIMD_COEF_32*5+(k&(SIMD_COEF_32-1))+(SIMD_COEF_32<<2)] = ctx2.SHA_H4;

		SHA1_Update(&ctx1,salt_buffer,salt_len);
		SHA1_Update(&ctx1,"\x0\x0\x0\x1",4);
		SHA1_Final((unsigned char*)tmp_hash,&ctx1);

		SHA1_Update(&ctx2,(unsigned char*)tmp_hash,SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char*)tmp_hash,&ctx2);

		// now convert this from flat into SIMD_COEF_32 buffers.
		// Also, perform the 'first' ^= into the crypt buffer.  NOTE, we are doing that in BE format
		// so we will need to 'undo' that in the end.
		o1[(k/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ+(k&(SIMD_COEF_32-1))]                = t_crypt[k*4+0] = ctx2.SHA_H0;
		o1[(k/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ+(k&(SIMD_COEF_32-1))+SIMD_COEF_32]       = t_crypt[k*4+1] = ctx2.SHA_H1;
		o1[(k/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ+(k&(SIMD_COEF_32-1))+(SIMD_COEF_32<<1)]  = t_crypt[k*4+2] = ctx2.SHA_H2;
		o1[(k/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ+(k&(SIMD_COEF_32-1))+SIMD_COEF_32*3]     = t_crypt[k*4+3] = ctx2.SHA_H3;
		o1[(k/SIMD_COEF_32)*SIMD_COEF_32*SHA_BUF_SIZ+(k&(SIMD_COEF_32-1))+(SIMD_COEF_32<<2)]                   = ctx2.SHA_H4;
	}

	for (i = 1; i < iteration_cnt; i++)
	{
		SIMDSHA1body((unsigned int*)t_sse_hash1, (unsigned int*)t_sse_hash1, (unsigned int*)t_sse_crypt1, SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		SIMDSHA1body((unsigned int*)t_sse_hash1, (unsigned int*)t_sse_hash1, (unsigned int*)t_sse_crypt2, SSEi_MIXED_IN|SSEi_RELOAD|SSEi_OUTPUT_AS_INP_FMT);
		// only xor first 16 bytes, since that is ALL this format uses
		for (k = 0; k < MS_NUM_KEYS; k++) {
			unsigned *p = &((unsigned int*)t_sse_hash1)[k/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32 + (k&(SIMD_COEF_32-1))];
			for (j = 0; j < 4; j++)
				t_crypt[k*4+j] ^= p[(j*SIMD_COEF_32)];
		}
	}
}

#else
/*
 * This function is derived from IEEE Std 802.11-2004, Clause H.4.
 * The main construction is from PKCS#5 v2.0.  It is tweaked a little
 * to remove some code not needed for our SHA1-128 output.
 */
static void pbkdf2(unsigned int _key[]) // key is also 'final' digest.
{
	SHA_CTX ctx1, ctx2, tmp_ctx1, tmp_ctx2;
	unsigned char ipad[SHA_CBLOCK], opad[SHA_CBLOCK];
	unsigned int tmp_hash[SHA_DIGEST_LENGTH/4];
	unsigned i, j;
	unsigned char *key = (unsigned char*)_key;

	for (i = 0; i < 16; i++) {
		ipad[i] = key[i]^0x36;
		opad[i] = key[i]^0x5C;
	}
	memset(&ipad[16], 0x36, sizeof(ipad)-16);
	memset(&opad[16], 0x5C, sizeof(opad)-16);

	SHA1_Init(&ctx1);
	SHA1_Init(&ctx2);

	SHA1_Update(&ctx1, ipad, SHA_CBLOCK);
	SHA1_Update(&ctx2, opad, SHA_CBLOCK);

	memcpy(&tmp_ctx1, &ctx1, sizeof(SHA_CTX));
	memcpy(&tmp_ctx2, &ctx2, sizeof(SHA_CTX));

	SHA1_Update(&ctx1, salt_buffer, salt_len);
	SHA1_Update(&ctx1, "\x0\x0\x0\x1", 4);
	SHA1_Final((unsigned char*)tmp_hash,&ctx1);

	SHA1_Update(&ctx2, (unsigned char*)tmp_hash, SHA_DIGEST_LENGTH);
	// we have to sha1 final to a 'temp' buffer, since we can only overwrite first 16 bytes
	// of the _key buffer.  If we overwrote 20 bytes, then we would lose the first 4 bytes
	// of the next element (and overwrite end of buffer on last element).
	SHA1_Final((unsigned char*)tmp_hash, &ctx2);

	// only copy first 16 bytes, since that is ALL this format uses
	memcpy(_key, tmp_hash, 16);

	for (i = 1; i < iteration_cnt; i++)
	{
		// we only need to copy the accumulator data from the CTX, since
		// the original encryption was a full block of 64 bytes.
#if HAVE_LIBCRYPTO
#define COPY_CTX(dst, src) \
		memcpy(&dst, &src, sizeof(SHA_CTX)-(64+sizeof(unsigned int)));
#elif SPH_64
#define COPY_CTX(dst, src) \
		memcpy(dst.val, src.val, 5 * sizeof(sph_u32)); \
		dst.count = src.count;
#else
#define COPY_CTX(dst, src) \
		memcpy(dst.val, src.val, 7 * sizeof(sph_u32));
#endif
		COPY_CTX(ctx1, tmp_ctx1)
		SHA1_Update(&ctx1, (unsigned char*)tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char*)tmp_hash, &ctx1);

		COPY_CTX(ctx2, tmp_ctx2)
		SHA1_Update(&ctx2, (unsigned char*)tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char*)tmp_hash, &ctx2);

		// only xor first 16 bytes, since that is ALL this format uses
		for (j = 0; j < 4; j++)
			_key[j] ^= tmp_hash[j];
	}
}
#endif


static int crypt_all(int *pcount, struct db_salt *salt)
{
	int count = *pcount;
	int i, t, t1;
	// Note, for a format like DCC2, there is little reason to optimize anything other
	// than the pbkdf2 inner loop.  The one exception to that, is the NTLM can be done
	// and known when to be done, only when the

	// now get NTLM of the password (MD4 of unicode)
	if (new_key) {
#if defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, key, md4hash)
#endif
		for (i = 0; i < count; ++i) {
			int utf16len;
			UTF16 pass_unicode[PLAINTEXT_LENGTH+1];
			MD4_CTX ctx;
			utf16len = enc_to_utf16(pass_unicode, PLAINTEXT_LENGTH, &key[(PLAINTEXT_LENGTH + 1)*i], strlen((char*)&key[(PLAINTEXT_LENGTH + 1)*i]));
			if (utf16len <= 0) {
				key[(PLAINTEXT_LENGTH + 1)*i-utf16len] = 0;
				if (utf16len != 0)
					utf16len = strlen16(pass_unicode);
			}
			MD4_Init(&ctx);
			MD4_Update(&ctx, pass_unicode, utf16len<<1);
			MD4_Final(&md4hash[HASH_LEN*i], &ctx);
		}
		new_key = 0;
	}

#ifdef _OPENMP
#if defined(WITH_UBSAN)
#pragma omp parallel for
#else
#pragma omp parallel for default(none) private(t) shared(count, salt_buffer, salt_len, crypt_out, md4hash)
#endif
#endif
	for (t1 = 0; t1 < count; t1 += MS_NUM_KEYS)	{
		MD4_CTX ctx;
		int i;
		t = t1 / MS_NUM_KEYS;
		for (i = 0; i < MS_NUM_KEYS; ++i) {
			// Get DCC1.  That is MD4( NTLM . unicode(lc username) )
			MD4_Init(&ctx);
			MD4_Update(&ctx, &md4hash[(t * MS_NUM_KEYS + i) * HASH_LEN], 16);
			MD4_Update(&ctx, salt_buffer, salt_len);
			MD4_Final((unsigned char*)&crypt_out[(t * MS_NUM_KEYS + i) * 4], &ctx);
			// now we have DCC1 (mscash) which is MD4 (MD4(unicode(pass)) . unicode(lc username))

#ifndef SIMD_COEF_32
			// Non-SSE: Compute DCC2 one at a time
			pbkdf2(&crypt_out[(t * MS_NUM_KEYS + i) * 4]);
#endif
		}
#ifdef SIMD_COEF_32
		// SSE: Compute DCC2 in parallel, once per thread
		pbkdf2_sse2(t);
#endif
	}
	return count;
}

struct fmt_main fmt_mscash2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH | 0x100,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_ENC,
		{ NULL },
		{ FORMAT_TAG2 },
		mscash2_common_tests
	}, {
		init,
		done,
		fmt_default_reset,
		mscash2_common_prepare,
		valid,
		mscash2_common_split,
		get_binary,
		get_salt,
		{ NULL },
		fmt_default_source,
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
